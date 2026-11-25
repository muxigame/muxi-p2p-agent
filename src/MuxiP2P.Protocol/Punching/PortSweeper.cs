using System.Net;
using System.Net.Sockets;

namespace BatterMC.Protocol;

/// <summary>
/// 单边端口扫描：锥形一侧去找对称型一侧朝我们新开的那个映射。
///
/// 为什么能扫中：对称型那一侧为了打洞已经朝我们公布的（稳定的）地址发过包，它的 NAT
/// 早为我们开好了口子，缺的只是我们不知道它用的是哪个端口；而它的端口是顺序分配的，
/// 就在它报上来的那个（或各个计数器）附近往上。
///
/// 窗口与节奏沿用实测定下来的值：报上来的端口往下 64、往上 2432，每个起点每轮 4 个
/// （50ms 一轮，约 80 包/秒），见原 UdpPuncher 里那几段说明——UDP 被运营商限速到 3 KB/s
/// 的线路上更快只会连准确地址那几个包一起被丢掉，而且在对端看来就是端口扫描。
/// </summary>
internal sealed class PortSweeper(IReadOnlyList<IPEndPoint> bases)
{
    private const int Below = 64;
    private const int Above = 2432;
    private const int PerRound = 4;
    private int _cursor;

    public IReadOnlyList<IPEndPoint> Bases { get; } = bases
        .Where(b => b.AddressFamily == AddressFamily.InterNetwork)
        .DistinctBy(b => b.ToString())
        .ToList();

    public async Task StepAsync(PunchContext context, CancellationToken ct)
    {
        var start = _cursor;
        _cursor += PerRound;
        foreach (var origin in Bases)
            for (var i = 0; i < PerRound; i++)
            {
                var offset = (start + i) % (Below + Above) - Below;
                if (offset == 0) continue;
                var port = origin.Port + offset;
                if (port is < 1 or > 65535) continue;
                await context.SendAsync(context.Main, new IPEndPoint(origin.Address, port), ct).ConfigureAwait(false);
            }
    }

    /// <summary>扫描起点：对端有计数器就从各计数器出发，否则从它报的每个候选出发。</summary>
    public static PortSweeper For(NatProfile peer, IReadOnlyList<IPEndPoint> candidates) =>
        new(peer.Counters.Count > 0
            ? peer.Counters.Select(c => new IPEndPoint(c.Address, c.Top)).ToList()
            : candidates);
}
