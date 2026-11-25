using System.Diagnostics;
using System.Net;
using System.Net.Quic;
using System.Text;
using BatterMC.Protocol;

namespace MuxiTunnel.Server;

/// <summary>
/// `muxi-p2p-agent selftest`: checks the pieces a direct tunnel needs on this machine
/// without a control plane or any credentials — msquic loads, the OpenSSL shim makes
/// the ephemeral certificate, and a QUIC listener and a connection on this machine
/// can echo a few bytes. It prints one JSON line and exits 0 when all of it works,
/// so a packager (Android, macOS) can tell a missing library from a network problem.
/// </summary>
internal static class SelfTest
{
    public static async Task<int> RunAsync()
    {
        var clock = Stopwatch.StartNew();
        string step = "support";
        try
        {
            var support = QuicTunnel.DescribeSupport();
            if (!QuicTunnel.IsSupported) return Report(false, step, support, clock);

            step = "certificate";
            var certificate = QuicTunnel.CreateEphemeralCertificate();

            step = "listen";
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var listener = await QuicTunnel.ListenAsync(
                0, certificate, System.Net.Sockets.AddressFamily.InterNetwork, timeout.Token).ConfigureAwait(false);
            var local = listener.LocalEndPoint;
            var peer = new IPEndPoint(local.Address.Equals(IPAddress.Any) ? IPAddress.Loopback : local.Address, local.Port);

            var serve = Task.Run(async () =>
            {
                await using var inbound = await listener.AcceptConnectionAsync(timeout.Token).ConfigureAwait(false);
                await using var stream = await inbound.AcceptInboundStreamAsync(timeout.Token).ConfigureAwait(false);
                var buffer = new byte[64];
                var read = await stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
                await stream.WriteAsync(buffer.AsMemory(0, read), completeWrites: true, timeout.Token).ConfigureAwait(false);
                // Wait for the client to finish reading before this side tears down.
                try { await stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false); } catch { }
            });

            step = "connect";
            await using var connection = await QuicTunnel.ConnectAsync(0, peer, timeout.Token).ConfigureAwait(false);
            step = "echo";
            await using var outbound = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, timeout.Token).ConfigureAwait(false);
            var ping = Encoding.ASCII.GetBytes("muxi-selftest");
            await outbound.WriteAsync(ping, timeout.Token).ConfigureAwait(false);
            var echo = new byte[64];
            var got = 0;
            while (got < ping.Length)
            {
                var n = await outbound.ReadAsync(echo.AsMemory(got), timeout.Token).ConfigureAwait(false);
                if (n == 0) break;
                got += n;
            }
            outbound.CompleteWrites();
            var ok = got == ping.Length && echo.AsSpan(0, got).SequenceEqual(ping);
            await serve.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
            return Report(ok, step, ok ? support : $"echo mismatch ({got} bytes)", clock);
        }
        catch (Exception error)
        {
            return Report(false, step, $"{error.GetType().Name}: {error.Message}", clock);
        }
    }

    private static int Report(bool ok, string step, string detail, Stopwatch clock)
    {
        Connect.Emit("selftest",
            ("ok", ok), ("step", step), ("detail", detail),
            ("ms", (long)clock.Elapsed.TotalMilliseconds),
            ("os", System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier));
        return ok ? 0 : 1;
    }
}
