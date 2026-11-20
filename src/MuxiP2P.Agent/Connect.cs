using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using BatterMC.Core;
using BatterMC.Protocol;

namespace MuxiTunnel.Server;

/// <summary>
/// <c>muxi-p2p-agent connect</c>: the connecting side as a local port forwarder.
///
/// Finds the agent through the control plane, tries its direct candidates (IPv6, LAN, mapped
/// port) with the TCP tunnel first and hole punching (UDP + QUIC, then TCP) after, then listens
/// on a loopback port and carries every local connection over the tunnel as one stream.
///
/// Speaks JSON lines on stdout so a host process can drive it: <c>{"event":"ready","port":N,
/// "route":"..."}</c> once usable, <c>{"event":"lost"}</c> when the tunnel dies (exit 4),
/// <c>{"event":"error","error":"..."}</c> when it cannot be built (exit 3). It also exits when its
/// stdin closes, so it never outlives the process that started it.
/// </summary>
internal static class Connect
{
    public static async Task<int> RunAsync(string[] args)
    {
        var controlPlane = Program.Value(args, "--control-plane") ?? Environment.GetEnvironmentVariable("MUXI_CONTROL_PLANE");
        var serverId = Program.Value(args, "--server-id");
        var reflector = Program.Value(args, "--reflector") ?? Environment.GetEnvironmentVariable("MUXI_REFLECTOR") ?? "";
        var listen = Program.Value(args, "--listen") ?? "127.0.0.1:0";
        var directOnly = args.Contains("--no-punch");
        if (string.IsNullOrWhiteSpace(controlPlane) || string.IsNullOrWhiteSpace(serverId))
        {
            Emit(new { @event = "error", error = "connect needs --control-plane and --server-id" });
            return 2;
        }
        ControlPlaneClient.SetHeaders(Headers(args));

        using var lifetime = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; lifetime.Cancel(); };
        _ = Task.Run(() =>
        {
            // The host closing our stdin (or dying) ends the forwarder.
            try { while (Console.In.Read() >= 0) { } } catch { }
            lifetime.Cancel();
        });

        IMuxiTunnel? tunnel;
        try
        {
            tunnel = await EstablishAsync(controlPlane, serverId, reflector, directOnly, lifetime.Token).ConfigureAwait(false);
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            Emit(new { @event = "error", error = error.Message });
            return 3;
        }
        if (tunnel is null)
        {
            Emit(new { @event = "error", error = "no route to the device" });
            return 3;
        }

        var endpoint = IPEndPoint.Parse(listen);
        var listener = new TcpListener(endpoint);
        listener.Start(64);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Emit(new { @event = "ready", port, route = tunnel.Describe });

        var watch = Task.Run(async () =>
        {
            while (!lifetime.IsCancellationRequested && tunnel.IsAlive)
                await Task.Delay(500, lifetime.Token).ConfigureAwait(false);
        });
        try
        {
            while (!lifetime.IsCancellationRequested)
            {
                var accept = listener.AcceptTcpClientAsync(lifetime.Token).AsTask();
                var done = await Task.WhenAny(accept, watch).ConfigureAwait(false);
                if (done == watch) break;
                var client = await accept.ConfigureAwait(false);
                client.NoDelay = true;
                _ = PipeAsync(client, tunnel, lifetime.Token);
            }
        }
        catch (OperationCanceledException) { }
        listener.Stop();
        var lost = !tunnel.IsAlive && !lifetime.IsCancellationRequested;
        P2PTunnel.DisposeInBackground(tunnel);
        if (lost)
        {
            Emit(new { @event = "lost" });
            return 4;
        }
        return 0;
    }

    private static IEnumerable<KeyValuePair<string, string>> Headers(string[] args)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] != "--header") continue;
            var raw = args[i + 1];
            var colon = raw.IndexOf(':');
            if (colon > 0) yield return new(raw[..colon].Trim(), raw[(colon + 1)..].Trim());
        }
        // A credential is better passed in the environment than on the command line.
        var env = Environment.GetEnvironmentVariable("MUXI_CONTROL_PLANE_HEADERS");
        if (string.IsNullOrWhiteSpace(env)) yield break;
        foreach (var line in env.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = line.IndexOf(':');
            if (colon > 0) yield return new(line[..colon].Trim(), line[(colon + 1)..].Trim());
        }
    }

    private static async Task<IMuxiTunnel?> EstablishAsync(
        string controlPlane, string serverId, string reflector, bool directOnly, CancellationToken ct)
    {
        var token = await ControlPlaneClient.FetchClientTokenAsync(controlPlane, serverId, TimeSpan.FromSeconds(15), ct)
            .ConfigureAwait(false) ?? throw new InvalidOperationException("the control plane gave no client token");
        var snapshot = await ControlPlaneClient.FetchAsync(controlPlane, serverId, TimeSpan.FromSeconds(15), ct)
            .ConfigureAwait(false) ?? throw new InvalidOperationException("the control plane is unreachable");
        if (!snapshot.Online) throw new InvalidOperationException("the device's tunnel agent is not registered");

        // 1. Direct: the agent's own addresses (IPv6, LAN, a router mapping), all at once.
        var direct = new List<Task<TunnelClient?>>();
        foreach (var candidate in snapshot.Candidates.Where(c => c.Kind != RouteKind.Relay))
        {
            direct.Add(TryDirectAsync(candidate, snapshot.TunnelPort, token, ct));
        }
        while (direct.Count > 0)
        {
            var finished = await Task.WhenAny(direct).ConfigureAwait(false);
            direct.Remove(finished);
            if (await finished.ConfigureAwait(false) is { } tunnel)
            {
                foreach (var other in direct)
                    _ = other.ContinueWith(t => { if (t.IsCompletedSuccessfully && t.Result is { } late) P2PTunnel.DisposeInBackground(late); },
                        TaskScheduler.Default);
                return tunnel;
            }
        }
        if (directOnly) return null;

        // 2. Hole punching through the reflectors and the control plane's rendezvous.
        if (string.IsNullOrWhiteSpace(reflector)) throw new InvalidOperationException("no direct route and no --reflector to punch with");
        var progress = new Progress<string>(text => Emit(new { @event = "progress", text }));
        return await P2PTunnel.EstablishAsync(controlPlane, serverId, token, reflector, progress, ct).ConfigureAwait(false);
    }

    private static async Task<TunnelClient?> TryDirectAsync(RouteCandidate candidate, int tunnelPort, string token, CancellationToken ct)
    {
        try
        {
            var addresses = IPAddress.TryParse(candidate.Host, out var literal)
                ? [literal]
                : await Dns.GetHostAddressesAsync(candidate.Host, ct).ConfigureAwait(false);
            foreach (var address in addresses)
            {
                try
                {
                    var timeout = TimeSpan.FromMilliseconds(candidate.ProbeTimeoutMs > 0 ? candidate.ProbeTimeoutMs : 2500);
                    return await TunnelClient.ConnectAsync(new IPEndPoint(address, tunnelPort), token, timeout, ct).ConfigureAwait(false);
                }
                catch (Exception error) when (error is SocketException or OperationCanceledException or IOException
                                                  or InvalidDataException or TimeoutException)
                {
                }
            }
        }
        catch (Exception error) when (error is SocketException or OperationCanceledException or ArgumentException)
        {
        }
        return null;
    }

    private static async Task PipeAsync(TcpClient client, IMuxiTunnel tunnel, CancellationToken ct)
    {
        using var _ = client;
        Stream remote;
        try
        {
            remote = await tunnel.OpenStreamAsync(ct).ConfigureAwait(false);
        }
        catch (Exception)
        {
            return;
        }
        await using (remote.ConfigureAwait(false))
        {
            var local = client.GetStream();
            using var both = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var up = CopyAsync(local, remote, both.Token);
            var down = CopyAsync(remote, local, both.Token);
            await Task.WhenAny(up, down).ConfigureAwait(false);
            both.Cancel();
            try { await Task.WhenAll(up, down).ConfigureAwait(false); } catch { }
        }
    }

    private static async Task CopyAsync(Stream from, Stream to, CancellationToken ct)
    {
        var buffer = new byte[64 * 1024];
        try
        {
            while (true)
            {
                var read = await from.ReadAsync(buffer, ct).ConfigureAwait(false);
                if (read <= 0) return;
                await to.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                await to.FlushAsync(ct).ConfigureAwait(false);
            }
        }
        catch (Exception error) when (error is IOException or OperationCanceledException or ObjectDisposedException
                                          or SocketException or InvalidOperationException)
        {
        }
    }

    private static readonly object EmitLock = new();

    internal static void Emit(object payload)
    {
        var line = JsonSerializer.Serialize(payload);
        lock (EmitLock)
        {
            Console.Out.WriteLine(line);
            Console.Out.Flush();
        }
    }
}
