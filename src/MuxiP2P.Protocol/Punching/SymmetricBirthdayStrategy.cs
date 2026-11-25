using System.Net;
using System.Net.Sockets;

namespace BatterMC.Protocol;

/// <summary>
/// 两侧都是对称型、但没法实时观测对方（对端是老版本、反射器不支持观测通道、或者有一侧
/// 端口无规律）时的兜底：双向顺序预测 + 随机偏移，碰运气（实测 两台实测机器之间 约 35~40%）。
///
/// 利用两边 NAT 大体顺序分配端口：
///
///   我方第 i 条新流的映射 ≈ 我方已报端口 + i（+ 漂移）
///   我方第 i 条新流的目标 = 对方已报端口 + i + r（r 随机 0..DriftSpread）
///
/// 对方做同样的事，某一对 (i, j) 恰好互相指向就通。和 0.8.8 的行为完全一样，所以和老版本
/// 的对端也对得上；同时照旧朝准确地址发（老版本对端也会）。不开诱饵——诱饵一开头就要各吃
/// 掉几十个端口，把两边的序号全打乱。
/// </summary>
internal sealed class SymmetricBirthdayStrategy : IPunchStrategy
{
    private const int FlowsPerRound = 3;
    private const int DriftSpread = 24;
    private const int ResendPerRound = 6;

    private List<IPEndPoint> _pools = [];
    private readonly List<IPEndPoint> _targets = [];
    private int _index;

    public string Describe { get; private set; } = "";

    public IReadOnlyList<Socket> ExtraSockets => [];

    public Task StartAsync(PunchContext context, CancellationToken ct)
    {
        _pools = PortPools(context.Candidates);
        Describe = $"两侧都是对称型（无法实时观测对方）：双向顺序预测，每轮新开 {FlowsPerRound} 条流、偏移 0~{DriftSpread}，"
                   + $"对端端口池 [{string.Join("，", _pools.Select(p => $"{p.Address}:{p.Port}+"))}]";
        return Task.CompletedTask;
    }

    public async Task TickAsync(PunchContext context, CancellationToken ct)
    {
        await context.SendAllAsync(context.Main, context.Exact, ct).ConfigureAwait(false);
        if (_pools.Count == 0) return;
        for (var k = 0; k < FlowsPerRound; k++, _index++)
        {
            var pool = _pools[_index % _pools.Count];
            var port = pool.Port + 1 + _index / _pools.Count + Random.Shared.Next(DriftSpread + 1);
            if (port > 65535) continue;
            var target = new IPEndPoint(pool.Address, port);
            _targets.Add(target);
            await context.SendAsync(context.Main, target, ct).ConfigureAwait(false);
        }
        for (var k = 0; k < ResendPerRound && _targets.Count > FlowsPerRound; k++)
            await context.SendAsync(context.Main,
                _targets[Random.Shared.Next(_targets.Count - FlowsPerRound)], ct).ConfigureAwait(false);
    }

    /// <summary>
    /// 对端报上来的端口按"池"分组，每组取最大的那个作起点。相距 64 以内的算同一段。
    /// </summary>
    internal static List<IPEndPoint> PortPools(IReadOnlyList<IPEndPoint> candidates)
    {
        var pools = new List<IPEndPoint>();
        foreach (var group in candidates.Where(c => c.AddressFamily == AddressFamily.InterNetwork)
                     .GroupBy(c => c.Address))
        {
            var ports = group.Select(c => c.Port).Distinct().OrderBy(p => p).ToList();
            if (ports.Count < 2) continue;
            var top = ports[0];
            for (var i = 1; i < ports.Count; i++)
            {
                if (ports[i] - ports[i - 1] > 64) pools.Add(new IPEndPoint(group.Key, top));
                top = ports[i];
            }
            pools.Add(new IPEndPoint(group.Key, top));
        }
        return pools;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
