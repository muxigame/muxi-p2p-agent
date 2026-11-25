namespace BatterMC.Protocol;

/// <summary>
/// 按两侧 NAT 类型的组合挑打洞策略。
///
/// | 本机 \ 对端      | 锥形 NAT1/2/3             | 对称型 NAT4                                  |
/// |------------------|---------------------------|----------------------------------------------|
/// | 锥形 NAT1/2/3    | <see cref="ConeStrategy"/> | <see cref="ConeVsSymmetricStrategy"/>        |
/// | 对称型 NAT4      | <see cref="SymmetricVsConeStrategy"/> | 都可预测且能观测：<see cref="SymmetricCounterStrategy"/>；否则 <see cref="SymmetricBirthdayStrategy"/> |
///
/// 两侧各自挑，挑法对称：每一侧都拿到了对方的画像，组合一致，所以两边的策略总是配套的。
/// 对端是老版本（没报画像）时按它的候选推断，落到的分支和老版本自己的行为一致。
/// </summary>
internal static class PunchPlanner
{
    public static IPunchStrategy Choose(NatProfile mine, NatProfile peer, PunchPlan plan)
    {
        // 本机类型不明（出口探测没探全）按锥形算：最多多扫一会儿，不会把能通的路堵死。
        var mineSymmetric = mine.Symmetric;
        var peerSymmetric = peer.Symmetric;
        if (!mineSymmetric && !peerSymmetric) return new ConeStrategy();
        if (!mineSymmetric) return new ConeVsSymmetricStrategy();
        if (!peerSymmetric) return new SymmetricVsConeStrategy();
        // 只看两侧都稳定一致的条件：是不是对称型、能不能用观测通道（过滤测试缓存 10 分钟）。
        // 不看"端口可不可预测"——那是按几个样本猜的，agent 公布的画像和它手里那个 socket 的
        // 画像可能一个判成顺序一个判成随机，两边就会挑出不配套的策略（实测一边按轮观测、
        // 另一边在盲猜，观测数一直是 0）。真是随机分配的，按轮观测也不会比盲猜更差。
        var counters = mine.Observable && peer.Observable
                       && plan.Reflector is not null
                       && Environment.GetEnvironmentVariable("MUXI_NO_COUNTER_PUNCH") != "1";
        return counters ? new SymmetricCounterStrategy() : new SymmetricBirthdayStrategy();
    }
}
