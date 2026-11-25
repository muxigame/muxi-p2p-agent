using System.Net.Sockets;

namespace BatterMC.Protocol;

/// <summary>
/// 本机锥形、对端对称型（NAT1/2/3 对 NAT4）。对端朝我们的地址发包用的是一个我们不知道的
/// 新端口，分两种情况：
///
///   本机 NAT1/NAT2（不看来源端口）：对端的包朝我们公布的地址一发就能进来，我们照着它的
///   真实来源回 Ack 就通了，根本不用找它的端口。只照准确地址打，3 秒都没听到再扫，防过滤
///   方式测错。
///
///   本机 NAT3 或过滤方式不明：它的包进不来，必须由我们去撞它那个新端口——从它的各个计数器
///   （没有就从它报的候选）往上扫，立刻开始，见 <see cref="PortSweeper"/>。
/// </summary>
internal sealed class ConeVsSymmetricStrategy : IPunchStrategy
{
    private PortSweeper? _sweeper;
    private TimeSpan _sweepAfter;

    public string Describe { get; private set; } = "";

    public IReadOnlyList<Socket> ExtraSockets => [];

    public Task StartAsync(PunchContext context, CancellationToken ct)
    {
        _sweeper = PortSweeper.For(context.Peer, context.Candidates);
        var lenient = context.Mine.Filtering is NatFiltering.EndpointIndependent or NatFiltering.AddressDependent;
        _sweepAfter = lenient ? TimeSpan.FromSeconds(3) : TimeSpan.Zero;
        Describe = lenient
            ? $"本机{context.Mine.Label}、对端对称型：本机不看来源端口，对端的包朝我们的地址一发就能进来，只打准确地址（3 秒不通再扫）"
            : $"本机{context.Mine.Label}、对端对称型：由我们去撞对端新开的端口，从 [{string.Join("，", _sweeper.Bases)}] 往上扫";
        return Task.CompletedTask;
    }

    public async Task TickAsync(PunchContext context, CancellationToken ct)
    {
        await context.SendAllAsync(context.Main, context.Exact, ct).ConfigureAwait(false);
        if (context.Elapsed >= _sweepAfter && _sweeper is not null)
            await _sweeper.StepAsync(context, ct).ConfigureAwait(false);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
