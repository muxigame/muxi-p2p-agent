using System.Net.Sockets;

namespace BatterMC.Protocol;

/// <summary>
/// 两侧都是锥形（NAT1/2/3 任意组合）：双方公布的地址就是真地址，各自朝对方的准确地址
/// 反复发，下一个 50ms 周期就通。
///
/// NAT3 对 NAT3 也只要这样：两边都朝对方的准确 IP:端口 发过包，过滤器都已经为对方开好口子。
///
/// 1.5 秒还没通，才在对方报的端口附近扫一扫——那说明它报上来的地址已经陈旧（映射被换掉了），
/// 不是常态。
/// </summary>
internal sealed class ConeStrategy : IPunchStrategy
{
    private static readonly TimeSpan SweepAfter = TimeSpan.FromSeconds(1.5);
    private PortSweeper? _sweeper;

    public string Describe => "两侧都是锥形：照对方公布的地址直接打（1.5 秒不通再在附近扫，防地址陈旧）";

    public IReadOnlyList<Socket> ExtraSockets => [];

    public Task StartAsync(PunchContext context, CancellationToken ct)
    {
        _sweeper = new PortSweeper(context.Candidates);
        return Task.CompletedTask;
    }

    public async Task TickAsync(PunchContext context, CancellationToken ct)
    {
        await context.SendAllAsync(context.Main, context.Exact, ct).ConfigureAwait(false);
        if (context.Elapsed > SweepAfter && _sweeper is not null)
            await _sweeper.StepAsync(context, ct).ConfigureAwait(false);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
