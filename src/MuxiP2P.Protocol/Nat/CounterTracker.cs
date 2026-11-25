using System.Net;

namespace BatterMC.Protocol;

/// <summary>
/// 跟踪一侧对称型 NAT 各个端口计数器的当前位置。
///
/// 输入是反射器看到的端口（那一侧的探测包），输出是"每个计数器下一个新映射会拿到
/// 哪个端口"。
///
/// 归属按"后继"判：计数器只会往上走，一个观测值属于当前值在它下面、而且差得不多
/// （1~<see cref="MaxStep"/>）的那个计数器，有几个就取最近的；比某个计数器的当前值小一点点
/// （≤ <see cref="Reorder"/>）的是到达乱序，算它的；都不是就是一个之前没见过的计数器。
///
/// 不能按"离谁近"归：实测机器 B 的两个计数器只隔 28（35150 / 35177），按距离会把它们并成
/// 一个、取较大的那个，于是落在较小那个上的流全部打空。线程安全：观测在收包线程上进，
/// 预测在打洞线程上读。
/// </summary>
public sealed class CounterTracker
{
    /// <summary>同一个计数器两次观测之间最多前进多少（一轮里自己的流 + 探测 + 别的程序）。</summary>
    public const int MaxStep = 24;

    /// <summary>
    /// 到达乱序：观测值比计数器当前值小这么多以内也算它的。一轮的几个探测是连着发的，
    /// 到达 NAT 的顺序实测能差 4 位。
    /// </summary>
    public const int Reorder = 6;

    private readonly object _gate = new();
    private readonly List<Counter> _counters = [];

    private sealed class Counter(IPAddress address, int top)
    {
        public IPAddress Address { get; } = address;
        public int Top { get; set; } = top;
        public int Seen { get; set; }
        public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.MinValue;
    }

    public CounterTracker(IEnumerable<PortCounter> initial)
    {
        foreach (var counter in initial) _counters.Add(new Counter(counter.Address, counter.Top));
    }

    /// <summary>观测过的条数（不含初始值）。</summary>
    public int Observations { get; private set; }

    public void Observe(IPAddress address, int port, DateTimeOffset? at = null)
    {
        lock (_gate)
        {
            Observations++;
            Counter? nearest = null;
            foreach (var counter in _counters)
            {
                if (!counter.Address.Equals(address)) continue;
                var step = port - counter.Top;
                if (step is > 0 and <= MaxStep && (nearest is null || step < port - nearest.Top))
                    nearest = counter;
            }
            nearest ??= _counters.FirstOrDefault(c => c.Address.Equals(address)
                                                     && c.Top - port is >= 0 and <= Reorder);
            if (nearest is null)
            {
                nearest = new Counter(address, port);
                _counters.Add(nearest);
            }
            nearest.Top = Math.Max(nearest.Top, port);
            nearest.Seen++;
            nearest.LastSeen = at ?? DateTimeOffset.UtcNow;
        }
    }

    public readonly record struct Snapshot(IPAddress Address, int Top, int Seen, DateTimeOffset LastSeen)
    {
        public override string ToString() => $"{Address}:{Top}";
    }

    public IReadOnlyList<Snapshot> Current()
    {
        lock (_gate)
            return _counters.Select(c => new Snapshot(c.Address, c.Top, c.Seen, c.LastSeen)).ToList();
    }

    public int Count
    {
        get { lock (_gate) return _counters.Count; }
    }
}
