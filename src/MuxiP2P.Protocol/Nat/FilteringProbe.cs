using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace BatterMC.Protocol;

/// <summary>
/// 测 NAT 的过滤方式（区分 NAT1/2/3），顺带确认反射器支持 MUXI-REFLECT/2 和观测通道。
///
/// 做法：开一个新 socket，只朝反射器的**一个**地址发三个请求，分别要求反射器从同一个
/// socket（same）、同一 IP 的另一个端口（port）、另一个 IP 的同一端口（ip）回话：
///
///   ip 那条能进来   → 谁都放行（NAT1）
///   port 那条能进来 → 只认 IP（NAT2）
///   只有 same 能进  → IP+端口都要对上（NAT3，或对称型）
///
/// 必须用新 socket：出口探测那个 socket 已经朝反射器的每个地址和端口都发过包，过滤器
/// 早为它们开好了口子，在它上面测什么都"能进来"。
///
/// 过滤方式是 NAT 的属性，不随 socket 变，所以结果按本地地址缓存一段时间。
/// </summary>
public static class FilteringProbe
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("MUXI-REFLECT/2 ");
    private static readonly string[] Modes = ["same", "port", "ip"];
    private static readonly TimeSpan Wait = TimeSpan.FromMilliseconds(900);
    private static readonly TimeSpan CacheFor = TimeSpan.FromMinutes(10);

    public sealed record Result(NatFiltering Filtering, bool ReflectorV2)
    {
        public static readonly Result Unknown = new(NatFiltering.Unknown, false);
    }

    private static readonly Dictionary<string, (Result Result, DateTimeOffset At)> Cache = new();

    public static async Task<Result> RunAsync(IPAddress local, IPEndPoint reflector, CancellationToken ct)
    {
        var key = $"{local}>{reflector}";
        lock (Cache)
            if (Cache.TryGetValue(key, out var cached) && DateTimeOffset.UtcNow - cached.At < CacheFor)
                return cached.Result;

        var result = await ProbeAsync(local, reflector, ct).ConfigureAwait(false);
        // 反射器一个都没回（被墙、旧版本）就别缓存，下次再试。
        if (result.ReflectorV2)
            lock (Cache) Cache[key] = (result, DateTimeOffset.UtcNow);
        return result;
    }

    private static async Task<Result> ProbeAsync(IPAddress local, IPEndPoint reflector, CancellationToken ct)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try { socket.Bind(new IPEndPoint(local, 0)); }
        catch (SocketException) { return Result.Unknown; }
        SilenceIcmpResets(socket);

        var tag = Random.Shared.Next().ToString("x");
        var heard = new Dictionary<string, bool>(StringComparer.Ordinal); // mode -> supported
        using var window = CancellationTokenSource.CreateLinkedTokenSource(ct);
        window.CancelAfter(Wait);

        async Task ReceiveAsync()
        {
            var buffer = new byte[1500];
            while (!window.IsCancellationRequested)
            {
                SocketReceiveFromResult received;
                try
                {
                    received = await socket.ReceiveFromAsync(buffer, SocketFlags.None,
                        new IPEndPoint(IPAddress.Any, 0), window.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { return; }
                catch (SocketException) { continue; }
                catch (ObjectDisposedException) { return; }
                if (Parse(buffer.AsSpan(0, received.ReceivedBytes), tag) is not { } reply) continue;
                // 按回包真实的来源判断，不信 via（反射器在端口转发后面时 via 是内网地址）：
                // port 那条必须同 IP 换端口，ip 那条必须换 IP，否则测的不是我们以为的东西。
                var from = (IPEndPoint)received.RemoteEndPoint;
                var shaped = reply.Unsupported || reply.Mode switch
                {
                    "same" => from.Equals(reflector),
                    "port" => from.Address.Equals(reflector.Address) && from.Port != reflector.Port,
                    _ => !from.Address.Equals(reflector.Address),
                };
                if (!shaped) continue;
                lock (heard) heard[reply.Mode] = !reply.Unsupported;
                lock (heard) if (heard.Count == Modes.Length) window.Cancel();
            }
        }

        var receiver = ReceiveAsync();
        try
        {
            for (var round = 0; round < 3 && !window.IsCancellationRequested; round++)
            {
                foreach (var mode in Modes)
                {
                    lock (heard) if (heard.ContainsKey(mode)) continue;
                    var payload = Magic.Concat(Encoding.ASCII.GetBytes($"f{tag}{mode[0]}{round} {mode}")).ToArray();
                    try { await socket.SendToAsync(payload, SocketFlags.None, reflector, window.Token).ConfigureAwait(false); }
                    catch (SocketException) { }
                    catch (OperationCanceledException) { break; }
                }
                try { await Task.Delay(250, window.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
            try { await Task.Delay(Timeout.Infinite, window.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }
        finally
        {
            window.Cancel();
            await receiver.ConfigureAwait(false);
        }
        ct.ThrowIfCancellationRequested();

        Dictionary<string, bool> seen;
        lock (heard) seen = new Dictionary<string, bool>(heard);
        if (!seen.ContainsKey("same")) return Result.Unknown;
        if (seen.TryGetValue("ip", out var ipOk) && ipOk) return new Result(NatFiltering.EndpointIndependent, true);
        if (seen.TryGetValue("port", out var portOk) && portOk) return new Result(NatFiltering.AddressDependent, true);
        // port 那条反射器根本做不到（单端口部署）时说不清，别瞎判成最严。
        return seen.TryGetValue("port", out var reached) && !reached
            ? new Result(NatFiltering.Unknown, true)
            : new Result(NatFiltering.AddressPortDependent, true);
    }

    private readonly record struct Reply(string Mode, bool Unsupported, IPEndPoint? Via);

    private static Reply? Parse(ReadOnlySpan<byte> data, string tag)
    {
        try
        {
            using var document = JsonDocument.Parse(data.ToArray());
            var root = document.RootElement;
            if (!root.TryGetProperty("nonce", out var nonce) || nonce.GetString() is not { } text) return null;
            if (!text.StartsWith("f" + tag, StringComparison.Ordinal) || text.Length < tag.Length + 3) return null;
            var mode = text[tag.Length + 1] switch { 's' => "same", 'p' => "port", 'i' => "ip", _ => null };
            if (mode is null) return null;
            var unsupported = root.TryGetProperty("unsupported", out _);
            IPEndPoint? via = null;
            if (root.TryGetProperty("via", out var viaText) && IPEndPoint.TryParse(viaText.GetString() ?? "", out var parsed))
                via = parsed;
            return new Reply(mode, unsupported, via);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }

    internal static void SilenceIcmpResets(Socket target)
    {
        if (!OperatingSystem.IsWindows()) return;
        try { target.IOControl(unchecked((int)0x9800000C), [0, 0, 0, 0], null); }
        catch (SocketException) { }
    }
}
