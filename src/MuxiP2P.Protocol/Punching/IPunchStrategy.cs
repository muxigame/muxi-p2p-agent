using System.Net;
using System.Net.Sockets;

namespace BatterMC.Protocol;

/// <summary>
/// 调用方交给打洞的额外信息：两侧的 NAT 画像、自己是哪一侧、反射器在哪。
/// 不给（老调用方）时退回原来的推断：本机类型看 sweepPorts，对端类型看候选。
/// </summary>
/// <param name="Side">'c' 发起方（客户端），'a' 应答方（agent）。观测通道靠它区分两侧。</param>
/// <param name="Reflector">观测通道用的反射器端点；null 时不用需要观测的策略。</param>
public sealed record PunchPlan(NatProfile Mine, NatProfile? Peer, char Side, IPEndPoint? Reflector);

/// <summary>
/// 打洞时"往哪儿发、发什么"的策略。收包、认 Ack、判成功、收尾都在 <see cref="UdpPuncher"/>
/// 里统一做，策略只管发：<see cref="TickAsync"/> 每 50ms 调一次，直到成功或预算耗尽。
///
/// 按两侧 NAT 类型的组合分开写，见 <see cref="PunchPlanner"/>。
/// </summary>
internal interface IPunchStrategy : IAsyncDisposable
{
    /// <summary>写进日志的一句话：为什么这么打。</summary>
    string Describe { get; }

    /// <summary>额外开的 socket（诱饵）。引擎会给它们挂收包循环，打通的可能是其中之一。</summary>
    IReadOnlyList<Socket> ExtraSockets { get; }

    Task StartAsync(PunchContext context, CancellationToken ct);

    Task TickAsync(PunchContext context, CancellationToken ct);
}

internal sealed class PunchContext
{
    public required Socket Main { get; init; }
    /// <summary>对端主候选（不含备用 socket 的出口）。</summary>
    public required IReadOnlyList<IPEndPoint> Candidates { get; init; }
    /// <summary>主候选 + 备用 socket 的出口："准确地址"那一类发送用它。</summary>
    public required IReadOnlyList<IPEndPoint> Exact { get; init; }
    public required ulong Session { get; init; }
    public required DateTimeOffset Started { get; init; }
    /// <summary>两边共用的时间起点：约定时刻（已经过了就是开打时刻）。</summary>
    public required DateTimeOffset Epoch { get; init; }
    public required NatProfile Mine { get; init; }
    public required NatProfile Peer { get; init; }
    public required PunchPlan Plan { get; init; }
    public Action<string>? Log { get; init; }
    /// <summary>发一个探路包（登记 nonce 好认回来的 Ack，计数）。</summary>
    public required Func<Socket, IPEndPoint, CancellationToken, Task> SendAsync { get; init; }

    public TimeSpan Elapsed => DateTimeOffset.UtcNow - Started;

    public async Task SendAllAsync(Socket socket, IEnumerable<IPEndPoint> targets, CancellationToken ct)
    {
        foreach (var target in targets)
            await SendAsync(socket, target, ct).ConfigureAwait(false);
    }
}
