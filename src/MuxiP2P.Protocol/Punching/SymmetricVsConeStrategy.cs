using System.Net.Sockets;

namespace BatterMC.Protocol;

/// <summary>
/// 本机对称型、对端锥形（NAT4 对 NAT1/2/3）。对端的地址稳定，我们朝它发就行；难点在
/// 反方向——对端要找到我们朝它新开的那个端口。
///
///   对端 NAT1/NAT2：它不看来源端口，我们的包一到它就收、按真实来源回 Ack，一个 socket 足够。
///
///   对端 NAT3 或不明：它得靠扫描来撞我们的端口（见 <see cref="ConeVsSymmetricStrategy"/>）。
///   多开 <see cref="DecoySockets"/> 个 socket 一起朝它的准确地址发，每个都是一个新端口，
///   它扫中任何一个都算通（生日攻击）：命中率从 M/K 变成 1−(1−M/K)^N。实测蜂窝单 socket
///   6 次 3 成，N=16 时理论上 1−0.5^16。这些 socket 都只朝**一个**目标发，不是端口扫描。
/// </summary>
internal sealed class SymmetricVsConeStrategy : IPunchStrategy
{
    private const int DecoySockets = 16;
    private readonly List<Socket> _decoys = [];

    public string Describe { get; private set; } = "";

    public IReadOnlyList<Socket> ExtraSockets => _decoys;

    public Task StartAsync(PunchContext context, CancellationToken ct)
    {
        var lenient = context.Peer.Filtering is NatFiltering.EndpointIndependent or NatFiltering.AddressDependent;
        if (!lenient)
        {
            var local = ((System.Net.IPEndPoint)context.Main.LocalEndPoint!).Address;
            for (var i = 0; i < DecoySockets; i++)
            {
                try
                {
                    var extra = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                    extra.Bind(new System.Net.IPEndPoint(local, 0));
                    FilteringProbe.SilenceIcmpResets(extra);
                    _decoys.Add(extra);
                }
                catch (SocketException) { break; }
            }
        }
        Describe = lenient
            ? $"本机对称型、对端{context.Peer.Label}：对端不看来源端口，朝它的准确地址发就够"
            : $"本机对称型、对端{context.Peer.Label}：本机映射对端预测不了，额外开 {_decoys.Count} 个端口一起打"
              + "（靠数量换对端扫描的命中率，不是端口扫描）";
        return Task.CompletedTask;
    }

    public async Task TickAsync(PunchContext context, CancellationToken ct)
    {
        foreach (var candidate in context.Exact)
        {
            await context.SendAsync(context.Main, candidate, ct).ConfigureAwait(false);
            foreach (var decoy in _decoys)
                await context.SendAsync(decoy, candidate, ct).ConfigureAwait(false);
        }
    }

    /// <summary>诱饵由引擎在定下赢家之后收（赢的那个不能关），这里不动。</summary>
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
