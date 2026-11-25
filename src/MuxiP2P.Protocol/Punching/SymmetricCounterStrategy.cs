using System.Net;
using System.Net.Sockets;

namespace BatterMC.Protocol;

/// <summary>
/// 两侧都是"端口可预测"的对称型（顺序分配或几个并行计数器），而且都能用反射器的观测通道：
/// 按轮同步、实时观测对方计数器的位置，每轮各开几条新流直指对方计数器的下一个端口。
///
/// 为什么这样能稳定打通（实测依据）：
///   · 两边都是"地址+端口相关"过滤，必须**两边同时**指对——我的流 A→B 要正好打在对方那条
///     B→A 流的端口上，反过来也一样。
///   · 两边的端口不是随机的，而是 1~3 个并行计数器，每个新映射随机落到其中一个、那个计数器 +1。
///     所以"对方下一个新映射的端口"只有 P 种可能：每个计数器当前值 +1。
///   · 计数器当前值靠观测得到：每轮开完流之后，每侧用几个新 socket 各朝反射器发一个探测包，
///     反射器把看到的端口记下来，另一侧去问（<see cref="ObservationChannel"/>）。
///
/// 只打"观测值 +1"不够：实测 实测机器 A 单计数器每轮按自己的流和探测该涨 4 格，实际涨了 7、3、9——
/// 本机别的程序（浏览器、DNS）也在用这个计数器。所以每轮每侧给对方的**每个**计数器各开
/// <see cref="FlowsPerCounter"/> 条流，目标在一个小窗口里随机撒：
///
///   窗口 = [观测值+1, 观测值 + 这一轮对方落在这个计数器上的流数 + <see cref="Drift"/>]
///
/// 对方这一轮的新流必然落在这个窗口里（计数器只往上走，起点就是观测值+1）。两边各在对方窗口里
/// 撒 N 个点，任意一对"我的流 f 打在对方流 g 的端口上、g 也正好打在 f 的端口上"就通；窗口宽度
/// 约等于对方这一轮在那个计数器上开的流数，算下来每轮期望约一对，一轮成功率六成左右，十来轮
/// 几乎必中。窗口靠实时观测压到十几个端口，这是和盲猜（窗口两百多）的根本区别。
///
/// 时间线（两边按约定时刻对齐，误差约一个 RTT）：
///   第 0 轮：只发探测，校准双方计数器（agent 的候选可能是十几秒前探的）。
///   第 k 轮：开 P_对方 条新流 → 发 2×P_本方 个探测 → 期间一直在拉对方的观测。
///   轮长 800ms：对方的探测要在下一轮开始前经反射器转到我们手里，实测到洛杉矶的 RTT
///   190ms、抖到 400ms。
/// 不再朝对方的"准确地址"发——对称型的准确地址本来就不存在，白白多吃十几个端口还把计数器搅乱。
/// </summary>
internal sealed class SymmetricCounterStrategy : IPunchStrategy
{
    public static readonly TimeSpan Slot = TimeSpan.FromMilliseconds(800);
    private const int ResendEveryTicks = 4;
    /// <summary>每轮给对方每个计数器开几条流。</summary>
    private const int FlowsPerCounter = 8;
    /// <summary>窗口里额外留给"本机别的程序"的余量（实测每轮 0~5 格）。</summary>
    private const int Drift = 6;

    private ObservationChannel? _channel;
    private int _slot = -1;
    private int _tick;
    private List<IPEndPoint> _current = [];
    private List<IPEndPoint> _previous = [];

    public string Describe { get; private set; } = "";

    public IReadOnlyList<Socket> ExtraSockets => [];

    public Task StartAsync(PunchContext context, CancellationToken ct)
    {
        var local = ((IPEndPoint)context.Main.LocalEndPoint!).Address;
        _channel = new ObservationChannel(local, context.Plan.Reflector!, context.Session, context.Plan.Side,
            context.Peer.Counters, context.Mine.Counters);
        _channel.Start(ct);
        Describe = $"两侧都是可预测的对称型：按轮同步（{Slot.TotalMilliseconds:0}ms 一轮），经反射器实时观测对方计数器，"
                   + $"每轮给对方每个计数器的下一个端口各开一条流；对方计数器初值 [{string.Join("，", context.Peer.Counters)}]";
        return Task.CompletedTask;
    }

    public async Task TickAsync(PunchContext context, CancellationToken ct)
    {
        _tick++;
        var now = DateTimeOffset.UtcNow;
        if (now < context.Epoch || _channel is null) return;
        var slot = (int)((now - context.Epoch) / Slot);
        if (slot != _slot)
        {
            _slot = slot;
            await RunSlotAsync(context, slot, ct).ConfigureAwait(false);
            return;
        }
        // 补发不开新映射：照顾"我的包到时对方的映射还没开"和丢包。
        if (_tick % ResendEveryTicks == 0)
        {
            await context.SendAllAsync(context.Main, _current, ct).ConfigureAwait(false);
            await context.SendAllAsync(context.Main, _previous, ct).ConfigureAwait(false);
        }
    }

    private async Task RunSlotAsync(PunchContext context, int slot, CancellationToken ct)
    {
        var channel = _channel!;
        var mine = Math.Max(1, Live(channel.Mine.Current()).Count);
        if (slot == 0)
        {
            await channel.ProbeAsync(Math.Clamp(2 * mine + 1, 3, 7), ct).ConfigureAwait(false);
            context.Log?.Invoke($"第 0 轮：发校准探测，本机计数器 {mine} 个");
            return;
        }

        var peer = Live(channel.Peer.Current());
        var targets = new List<IPEndPoint>();
        var windows = new List<string>();
        var now = DateTimeOffset.UtcNow;
        // 对方这一轮给我们每个计数器各开 FlowsPerCounter 条，平摊到它自己的计数器上。
        var landing = (int)Math.Ceiling(FlowsPerCounter * (double)mine / Math.Max(1, peer.Count));
        foreach (var counter in peer)
        {
            // 上一轮对方的探测没落到这个计数器上：它已经被对方上一轮的流推上去了一截，
            // 起点往后挪、窗口也放宽。
            var stale = counter.LastSeen == DateTimeOffset.MinValue
                ? Math.Min(slot, 3)
                : Math.Min(3, Math.Max(0, (int)Math.Round((now - counter.LastSeen) / Slot) - 1));
            var start = counter.Top + 1 + stale * landing;
            var width = landing + Drift + stale * Drift;
            windows.Add($"{start}~{start + width - 1}");
            foreach (var port in Pick(start, width, FlowsPerCounter))
                if (port is >= 1 and <= 65535) targets.Add(new IPEndPoint(counter.Address, port));
        }
        _previous = _current;
        _current = targets;
        // 新流：每个目标都是没发过的地址，各开一个新映射。
        await context.SendAllAsync(context.Main, targets, ct).ConfigureAwait(false);
        // 紧接着探测：探测落在哪个计数器上，就把那个计数器（含刚才的新流）的位置报给对方。
        await channel.ProbeAsync(Math.Clamp(2 * mine, 2, 6), ct).ConfigureAwait(false);

        if (slot <= 3 || slot % 4 == 0)
            context.Log?.Invoke($"第 {slot} 轮：对方计数器 [{string.Join("，", peer)}]"
                                + $"（已观测 {channel.Peer.Observations} 条），本轮在 [{string.Join("，", windows)}] 里撒 {targets.Count} 条，"
                                + $"本机计数器 {mine} 个");
    }

    /// <summary>[start, start+width) 里不重复地随机挑 count 个（窗口不够大就全挑）。</summary>
    private static IEnumerable<int> Pick(int start, int width, int count)
    {
        var all = Enumerable.Range(start, Math.Max(1, width)).ToArray();
        Random.Shared.Shuffle(all);
        return all.Take(count);
    }

    /// <summary>
    /// 只留观测到过的计数器：画像里带来的初值可能是十几秒前的（agent 的候选按 15 秒保鲜），
    /// 校准之后一次都没再出现的那个多半早就不用了，每轮还朝它开一条流纯属浪费。一个都没观测到
    /// （对端没参与观测）时退回全部初值。
    /// </summary>
    private static List<CounterTracker.Snapshot> Live(IReadOnlyList<CounterTracker.Snapshot> all)
    {
        var seen = all.Where(c => c.Seen > 0).ToList();
        if (seen.Count == 0) return all.ToList();
        // 被后继规则甩下的旧条目（一次跳得太远、换成了新条目）：最近两轮都没出现过的不要了；
        // 最多留最近的 <see cref="MaxCounters"/> 个——实测机器 B 一度被拆成 6~8 段，每轮 32 条流
        // 摊到一堆窗口里，密度反而掉下来。
        var latest = seen.Max(c => c.LastSeen);
        return seen.Where(c => latest - c.LastSeen < 2 * Slot)
            .OrderByDescending(c => c.LastSeen)
            .Take(MaxCounters)
            .ToList();
    }

    private const int MaxCounters = 3;

    public async ValueTask DisposeAsync()
    {
        if (_channel is { } channel)
        {
            _channel = null;
            await channel.DisposeAsync().ConfigureAwait(false);
        }
    }
}
