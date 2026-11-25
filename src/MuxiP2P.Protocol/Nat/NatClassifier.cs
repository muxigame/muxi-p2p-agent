using System.Net;
using System.Net.Sockets;

namespace BatterMC.Protocol;

/// <summary>
/// 把出口探测和过滤测试的结果归成 <see cref="NatProfile"/>。全是纯函数，方便单独验证。
/// </summary>
public static class NatClassifier
{
    /// <summary>
    /// 两个端口相距超过这么多就算不同的计数器。并行计数器的间距不固定：实测机器 A 实测 120~133，
    /// 机器 B 只有 28；而同一个计数器在一次探测（几个包、几十毫秒）里只前进一两格。
    /// </summary>
    public const int CounterGap = 16;

    /// <summary>同一个计数器相邻两次新映射之间允许的最大步长（中间被别的连接插队）。</summary>
    public const int MaxStep = 24;

    /// <summary>超过这么多个计数器就不当计数器看了——那是随机分配。</summary>
    public const int MaxCounters = 4;

    /// <summary>
    /// 从一个 socket 发往几个不同目标时拿到的映射判断端口分配方式。
    ///
    /// **不看顺序**：这几个包几乎同时发出，到达 NAT 的先后和发送顺序可以差好几位（实测机器 B
    /// 依次发出拿到 35229、35233、35232、35234、35231、35230——明明是连续的一段）。
    ///
    /// 做法是按端口聚类（相距超过 <see cref="CounterGap"/> 算不同的段）：
    ///   · 段数不超过 <see cref="MaxCounters"/>、至少有一段不止一个端口、而且每段都很紧凑
    ///     （跨度不超过 个数 × <see cref="MaxStep"/>）→ 计数器分配，段数就是计数器个数；
    ///   · 否则随机——随机分配的几个样本会散落在整个端口空间里，几乎每个都自成一段。
    /// </summary>
    public static (NatAllocation Allocation, List<PortCounter> Counters) Allocation(IReadOnlyList<IPEndPoint> sample)
    {
        var v4 = sample.Where(x => x.AddressFamily == AddressFamily.InterNetwork).ToList();
        if (v4.Count == 0) return (NatAllocation.Unknown, []);
        if (v4.Select(x => x.ToString()).Distinct().Count() == 1)
            return (NatAllocation.Stable, []);

        var clusters = new List<(IPAddress Address, List<int> Ports)>();
        foreach (var group in v4.GroupBy(x => x.Address))
        {
            var ports = group.Select(x => x.Port).Distinct().OrderBy(x => x).ToList();
            var current = new List<int> { ports[0] };
            for (var i = 1; i < ports.Count; i++)
            {
                if (ports[i] - ports[i - 1] > CounterGap)
                {
                    clusters.Add((group.Key, current));
                    current = [];
                }
                current.Add(ports[i]);
            }
            clusters.Add((group.Key, current));
        }

        var perAddress = clusters.GroupBy(c => c.Address).Max(g => g.Count());
        var compact = clusters.All(c => c.Ports[^1] - c.Ports[0] <= c.Ports.Count * MaxStep);
        var anyRun = clusters.Any(c => c.Ports.Count > 1);
        if (perAddress > MaxCounters || !compact || !anyRun)
            return (NatAllocation.Random, []);
        var counters = clusters.Select(c => new PortCounter(c.Address, c.Ports[^1])).ToList();
        return (perAddress == 1 ? NatAllocation.Sequential : NatAllocation.MultiCounter, counters);
    }

    /// <summary>
    /// 不知道顺序时（对端是老版本、只给了一堆候选）按端口聚类：同一个 IP 上相距不超过
    /// <see cref="CounterGap"/> 的算一段，每段取最大值。
    /// </summary>
    public static List<PortCounter> Counters(IEnumerable<IPEndPoint> endpoints)
    {
        var result = new List<PortCounter>();
        foreach (var group in endpoints.Where(x => x.AddressFamily == AddressFamily.InterNetwork).GroupBy(x => x.Address))
        {
            var ports = group.Select(x => x.Port).Distinct().OrderBy(x => x).ToList();
            var top = ports[0];
            for (var i = 1; i < ports.Count; i++)
            {
                if (ports[i] - ports[i - 1] > CounterGap) result.Add(new PortCounter(group.Key, top));
                top = ports[i];
            }
            result.Add(new PortCounter(group.Key, top));
        }
        return result;
    }

    /// <summary>
    /// 汇总：映射看出口探测（任意两个目标见到的映射不同 = 地址相关），过滤看
    /// <see cref="FilteringProbe"/>，分配方式看映射序列。
    /// </summary>
    public static NatProfile Classify(NatDiscovery.Result discovery, FilteringProbe.Result filtering)
    {
        if (discovery.Candidates.Count == 0)
            return NatProfile.Unknown with { Filtering = filtering.Filtering, Observable = filtering.ReflectorV2 };
        if (!discovery.AddressDependent)
            return new NatProfile(NatMapping.EndpointIndependent, filtering.Filtering, NatAllocation.Stable, [],
                filtering.ReflectorV2);
        var (allocation, counters) = Allocation(discovery.Candidates);
        if (allocation == NatAllocation.Stable) allocation = NatAllocation.Unknown;
        return new NatProfile(NatMapping.AddressDependent, filtering.Filtering, allocation,
            counters.Count > 0 ? counters : Counters(discovery.Candidates), filtering.ReflectorV2);
    }
}
