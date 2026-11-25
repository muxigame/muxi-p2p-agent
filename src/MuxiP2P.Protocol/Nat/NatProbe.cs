using System.Net;
using System.Net.Sockets;

namespace BatterMC.Protocol;

/// <summary>客户端和 agent 共用的那几步：找反射器、测过滤方式、出画像。</summary>
public static class NatProbe
{
    /// <summary>反射器列表里第一个能解析出 IPv4 的地址，配上给定端口。观测通道和过滤测试都用它。</summary>
    public static async Task<IPEndPoint?> ReflectorAsync(string hosts, int port, CancellationToken ct)
    {
        foreach (var host in hosts.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (IPAddress.TryParse(host, out var literal))
            {
                if (literal.AddressFamily == AddressFamily.InterNetwork) return new IPEndPoint(literal, port);
                continue;
            }
            try
            {
                var resolved = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
                if (resolved.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) is { } address)
                    return new IPEndPoint(address, port);
            }
            catch (SocketException) { }
        }
        return null;
    }

    /// <summary>过滤测试；没有反射器时直接"不知道"。</summary>
    public static Task<FilteringProbe.Result> FilteringAsync(IPAddress local, IPEndPoint? reflector, CancellationToken ct) =>
        reflector is null
            ? Task.FromResult(FilteringProbe.Result.Unknown)
            : FilteringProbe.RunAsync(local, reflector, ct);
}
