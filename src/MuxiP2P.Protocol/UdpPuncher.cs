using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace BatterMC.Protocol;

/// <summary>
/// UDP 打洞。两端在约定时刻同时朝对方的**全部**候选地址猛发探路包。
///
/// 原理：NAT 只放行"本端先发过包的那个对端地址"回来的流量。所以单边发起没用
/// ——先到的那个包在对方 NAT 上没有对应映射，会被当成未知连接丢掉。两边同时发，
/// 各自的出站包在自己这侧开出映射，随后对方的包就能进来了。
///
/// 成功判据是收到 <see cref="PunchProtocol.Kind.Ack"/>：那说明"我发出去的包到了
/// 对面"且"对面的回包也到了我这里"，双向都通。只收到对方的 Punch 不算——那只
/// 证明单向。
///
/// 这里只是引擎：收包、回 Ack、判成功、收尾。**往哪儿发**按两侧 NAT 类型的组合分到
/// Punching/ 下的各个策略里（锥形对锥形、锥形对对称、对称对锥形、对称对对称的两种），
/// 由 <see cref="PunchPlanner"/> 挑。
/// </summary>
public static class UdpPuncher
{
    /// <summary>发包间隔。密一点能抢在对方 NAT 映射老化之前，但也别把线路打满。</summary>
    private static readonly TimeSpan SendInterval = TimeSpan.FromMilliseconds(50);

    /// <summary>
    /// 自己这侧成功之后，还要继续替对方回 Ack 的**上限**。
    ///
    /// 两侧极少同时成功：先收到 Ack 的那一方如果立刻收摊，对方的探路包就没人
    /// 应答，会一直打到预算耗尽然后判失败——一边以为通了、一边以为没通。
    ///
    /// 但这曾经是**无条件**等满 2 秒，而且 elapsed 在它之后才算，于是日志里
    /// "打洞成功用时"永远是 2.0 秒出头——那个高度一致的数字来自这个常量，不是网络。
    /// 减掉它，实测的真实打洞时延是 20~197ms。更糟的是这 2 秒是真实阻塞：它挡在
    /// udp.Close() 和 QUIC 接手之间，两侧并行叠加，白白占掉总建立时延的约四分之一。
    ///
    /// 现在它只是上限。正常情况下 <c>punchesHeard &gt; 0</c> 就说明我们已经替对端
    /// 回过 Ack，那之后对端能否确认已经不取决于我们再多留多久——再留
    /// <see cref="AckRedundancy"/> 就够冗余了。
    /// </summary>
    private static readonly TimeSpan AckGrace = TimeSpan.FromSeconds(2);

    /// <summary>
    /// 已经回过 Ack 之后再多留一会儿，防那一个 Ack 正好丢了。
    ///
    /// 三个 <see cref="SendInterval"/>：对端每 50ms 还会再打一次探路包，我们会再回
    /// 一次。固定等 2 秒相比之下并没有多给任何保障——只是等了 40 个间隔而不是 3 个。
    /// </summary>
    private static readonly TimeSpan AckRedundancy = TimeSpan.FromMilliseconds(150);

    /// <param name="PeerLoadRequest">
    /// 打洞期间对端已经发来的洞压测请求（nonce 里编着计划）。对端只有在它自己判定
    /// 打通之后才会发这个包，所以收到它本身就是成功的证据；而且它已经被打洞的收包
    /// 循环吃掉了，必须原样交给应答方，否则对端要等一次 250ms 的重发。
    /// </param>
    public sealed record Outcome(
        IPEndPoint? Peer,
        TimeSpan Elapsed,
        int Sent,
        int PunchesHeard,
        IReadOnlyList<IPEndPoint> HeardFrom,
        Socket? Winner = null,
        ulong? PeerLoadRequest = null,
        bool PeerFinished = false)
    {
        public bool Success => Peer is not null;
    }

    /// <summary>
    /// 应答方（agent）在自己开了诱饵时，打通后再等对端表态的上限。
    ///
    /// 两边各自认定的那一对端口可能不同（谁的 Ack 先到谁就是赢家）。对端判定成功后发来的
    /// 第一个压测请求会指明它真正在用的那一对，但前提是我们那一侧对应的诱饵还开着——原先
    /// 成功 150ms 后就把没赢的诱饵全关了，对端选中的恰好是别的那个时，它的压测请求和 QUIC
    /// 都会打到一个已经关掉的端口上。只在应答方、且确实开了诱饵时才等。
    /// </summary>
    private static readonly TimeSpan PeerChoiceWait = TimeSpan.FromMilliseconds(600);

    public static async Task<Outcome> PunchAsync(
        Socket socket,
        IReadOnlyList<IPEndPoint> peerCandidates,
        ulong session,
        byte[] secret,
        DateTimeOffset punchAt,
        TimeSpan budget,
        bool sweepPorts,
        Action<string>? log,
        CancellationToken ct,
        IReadOnlyList<IPEndPoint>? alternates = null,
        bool awaitPeerChoice = false,
        PunchPlan? plan = null)
    {
        if (peerCandidates.Count == 0)
            return new Outcome(null, TimeSpan.Zero, 0, 0, [], null);
        // 对端备用 socket 的出口（见 P2PTags.UdpAlternate）：照准确地址一样打，诱饵也朝它们
        // 发，但不参与对称型判断、也不扫——它们不是"同一个 socket 的多个映射"。
        var exact = alternates is { Count: > 0 }
            ? peerCandidates.Concat(alternates.Where(a => !peerCandidates.Contains(a))).ToList()
            : peerCandidates;

        // Windows 上 UDP socket 收到 ICMP「端口不可达」之后，下一次 Receive 会抛
        // WSAECONNRESET。端口扫描必然打中大量关闭的端口，几千个 ICMP 回来会把
        // 接收循环反复打断，严重时把队列撑爆（实测 SocketException 10055）。
        // SIO_UDP_CONNRESET 关掉这个行为，让 socket 老老实实只管收包。
        static void SilenceIcmpResets(Socket target)
        {
            if (!OperatingSystem.IsWindows()) return;
            try { target.IOControl(unchecked((int)0x9800000C), [0, 0, 0, 0], null); }
            catch (SocketException) { /* 不支持就算了，只是少一层保护 */ }
        }
        SilenceIcmpResets(socket);

        // 两侧的 NAT 画像。老调用方不给 plan：本机类型按 sweepPorts（"我的地址能被对方提前
        // 知道" = 端点无关），对端按候选推断——落到的策略和改版前的行为一致。
        var myNat = plan?.Mine is { Mapping: not NatMapping.Unknown } given
            ? given
            : sweepPorts
                ? new NatProfile(NatMapping.EndpointIndependent, NatFiltering.Unknown, NatAllocation.Stable, [], false)
                : new NatProfile(NatMapping.AddressDependent, NatFiltering.Unknown, NatAllocation.Unknown, [], false);
        var peerNat = plan?.Peer ?? NatProfile.Infer(peerCandidates);
        plan ??= new PunchPlan(myNat, null, 'c', null);
        await using var strategy = PunchPlanner.Choose(myNat, peerNat, plan);

        // 自己发出去的 nonce。收到 Ack 时用它确认"这是对我那一发的回应"，
        // 而不是别人重放的旧包。
        var outstanding = new ConcurrentDictionary<ulong, byte>();
        // 连"是哪个 socket 听到的"一起记：兜底路径（没收到 Ack 但收到过对端探路包）
        // 也要能说出该把哪个本地端口交给 QUIC。
        var heardFrom = new ConcurrentDictionary<string, (IPEndPoint Peer, Socket Via)>();
        var punchesHeard = 0;
        var strangers = 0;
        var sent = 0;

        // 成功时必须连"是哪个 socket 收到的"一起记下来：多开了诱饵之后，打通的那条
        // 路属于某一个具体的本地端口，NAT 映射按本地端口记账——交给 QUIC 的必须是
        // 那一个，拿错了等于把刚打好的洞扔了。
        var success = new TaskCompletionSource<(IPEndPoint Peer, Socket Via)>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        // 对端已经收工、开始问压测了：它不再需要我们的 Ack，收尾宽限一律免掉。
        var peerDone = 0;
        var peerFinished = 0;
        long peerLoadRequest = 0;
        // 已经靠 Ack 记下一对之后，对端的压测请求又指明了另一对：以后者为准。
        Tuple<IPEndPoint, Socket>? overrideWinner = null;
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);

        async Task ReceiveLoopAsync(Socket mine)
        {
            var buffer = new byte[2048];
            while (!stop.IsCancellationRequested)
            {
                SocketReceiveFromResult received;
                try
                {
                    received = await mine.ReceiveFromAsync(
                        buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), stop.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) { return; }
                catch (ObjectDisposedException) { return; }
                catch (SocketException) { continue; }

                var packet = PunchProtocol.Parse(buffer.AsSpan(0, received.ReceivedBytes), secret);
                if (packet is null || packet.Value.Session != session)
                {
                    // 到了但认不出来：HMAC 不对（两边密钥派生不一致）或会话号不匹配。
                    // 必须单独计数——否则它和"什么都没到"在日志里长得一模一样，
                    // 而这两者一个是代码 bug、一个是网络不通，排查方向完全相反。
                    //
                    // 只数**长得像我们的包**（开头是魔数）的那些。出口探测迟到的反射器
                    // 回包（JSON）也会落在这个 socket 上，把它们算进来会让日志错误地
                    // 断言"密钥对不上、是代码问题"，把排查引到完全错误的方向。
                    if (received.ReceivedBytes >= 4
                        && System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(buffer) == PunchProtocol.Magic)
                        Interlocked.Increment(ref strangers);
                    continue;
                }
                var from = (IPEndPoint)received.RemoteEndPoint;

                switch (packet.Value.Type)
                {
                    case PunchProtocol.Kind.Punch:
                        // 对方的探路包到了，说明这个方向通了。回一个 Ack，让对方也确认。
                        Interlocked.Increment(ref punchesHeard);
                        heardFrom.TryAdd(from.ToString(), (from, mine));
                        try
                        {
                            var ack = PunchProtocol.Build(
                                PunchProtocol.Kind.Ack, session, packet.Value.Nonce, secret);
                            // 必须从收到它的那个 socket 回：源端口一变，对端 NAT 的
                            // 过滤就对不上，这个 Ack 等于没发。
                            await mine.SendToAsync(ack, SocketFlags.None, from, stop.Token)
                                .ConfigureAwait(false);
                        }
                        catch (Exception e) when (e is SocketException or OperationCanceledException) { }
                        break;

                    case PunchProtocol.Kind.Ack:
                        if (outstanding.ContainsKey(packet.Value.Nonce))
                            success.TrySetResult((from, mine));
                        break;

                    // 对端判定打通之后会立刻朝**它认定的那一对端口**发压测请求。
                    //
                    // 这比 Ack 更有信息量：它告诉我们对端实际在用哪个外部端口。实测蜂窝
                    // 那侧开了诱饵端口时，两边各自认定的端口对经常不是同一对——服务端
                    // 记的是 :6535，而客户端真正在用的是 :6376。服务端照 :6535 等压测
                    // 请求，6 次里 5 次一个都没等到，白耗 1.2 秒，预热形同虚设。
                    // 以对端发来的这个包为准，两边就一定落在同一对上。
                    // 对端连压测都做完了（或者压测被关了、直接收工）：同样是"它已经判定打通、
                    // 而且就在用这一对"的证据。不接住它的话，应答方要白等满第一个请求的
                    // 耐心（600ms）才去起 QUIC 监听，对端的第一个 Initial 就被吞了。
                    case PunchProtocol.Kind.LoadDone:
                        Interlocked.Exchange(ref peerFinished, 1);
                        Interlocked.Exchange(ref peerDone, 1);
                        if (!success.TrySetResult((from, mine)))
                            Volatile.Write(ref overrideWinner, Tuple.Create(from, mine));
                        break;

                    case PunchProtocol.Kind.LoadRequest:
                        Interlocked.Exchange(ref peerLoadRequest, (long)packet.Value.Nonce);
                        Interlocked.Exchange(ref peerDone, 1);
                        // 覆盖掉可能已经记下的另一对：对端认的那一对才是之后真正走流量的。
                        if (!success.TrySetResult((from, mine)))
                            Volatile.Write(ref overrideWinner, Tuple.Create(from, mine));
                        break;
                }
            }
        }

        var receivers = new List<Task> { Task.Run(() => ReceiveLoopAsync(socket), stop.Token) };
        var extras = new List<Socket>();

        // 拿到会合信息就开打，不再干等约定时刻。
        //
        // 约定时刻原本是为了"两边同时发"，但 UDP 打洞并不需要同时：先发的一方只是
        // 在自己的 NAT 上先开了口子，它发到对面的包被对面 NAT 丢掉，无害；等对面也
        // 开始发，下一个 50ms 周期就通了。真正决定何时能通的是**较晚那一方何时开始
        // 发**，而约定时刻只是给较晚那一方（agent 轮询取件）留的余量。
        //
        // 实测这一格固定 4.0 秒，占建立总时长的三分之一，而 agent 取件实际只要
        // 0.1~1.2 秒。现在两边都是拿到就发，预算的终点仍按约定时刻 + 预算算，
        // 所以对端是旧版本、仍在等约定时刻时，我们照样陪它打满原来那一段。
        var delay = punchAt - DateTimeOffset.UtcNow;
        var started = DateTimeOffset.UtcNow;
        var deadline = (delay > TimeSpan.Zero ? punchAt : started) + budget;

        // 把对端地址写出来，不只写个数。打洞失败时最要紧的问题是"我打的这个地址
        // 到底对不对"——两边日志各有一半，只有都印出地址才能对出是谁的候选陈旧了。
        log?.Invoke($"开始打洞：对端 [{string.Join("，", peerCandidates)}]"
                    + (exact.Count > peerCandidates.Count
                        ? $"，备用 [{string.Join("，", exact.Skip(peerCandidates.Count))}]" : "")
                    + $"，预算 {budget.TotalSeconds:0.#}s"
                    + (delay > TimeSpan.Zero ? $"（比约定时刻早 {delay.TotalMilliseconds:0} ms 开打）" : ""));
        log?.Invoke($"本机 {myNat.Describe()}；对端 {peerNat.Describe()}"
                    + (plan.Peer is null ? "（对端没报画像，按候选推断）" : ""));

        var context = new PunchContext
        {
            Main = socket,
            Candidates = peerCandidates,
            Exact = exact,
            Session = session,
            Started = started,
            Epoch = delay > TimeSpan.Zero ? punchAt : started,
            Mine = myNat,
            Peer = peerNat,
            Plan = plan,
            Log = log,
            SendAsync = async (via, target, token) =>
                sent += await SendPunchAsync(via, target, session, secret, outstanding, token).ConfigureAwait(false),
        };
        await strategy.StartAsync(context, ct).ConfigureAwait(false);
        log?.Invoke(strategy.Describe);
        foreach (var extra in strategy.ExtraSockets)
        {
            SilenceIcmpResets(extra);
            extras.Add(extra);
            var mineSocket = extra;
            receivers.Add(Task.Run(() => ReceiveLoopAsync(mineSocket), stop.Token));
        }

        while (DateTimeOffset.UtcNow < deadline && !success.Task.IsCompleted && !ct.IsCancellationRequested)
        {
            await strategy.TickAsync(context, ct).ConfigureAwait(false);
            var finished = await Task.WhenAny(success.Task, Task.Delay(SendInterval, ct))
                .ConfigureAwait(false);
            if (finished == success.Task) break;
        }

        // 成功后多留一会儿接收循环，好让还在打的对方能收到我们的 Ack。
        //
        // 判据是"我们是否已经替对端回过 Ack"，不是固定时长：收到过对端的探路包
        // （punchesHeard > 0）就意味着接收循环已经朝它回过 Ack。等到这一刻为止，
        // 再补一小段冗余就收工。
        //
        // 还没收到过对端探路包的情况也真实存在——对端靠端口扫描找到我们时，它的
        // 探路包打的是陈旧候选、从没到过我们这儿，我们只收到它的 Ack。那种情况下
        // 才需要一直等到 AckGrace 上限，让它的扫描包有机会到达。
        //
        // 对端已经发来压测请求时整段免掉：那说明它自己早就判定成功了，不再需要我们的 Ack。
        if (success.Task.IsCompletedSuccessfully && Volatile.Read(ref peerDone) == 0)
        {
            var cap = DateTimeOffset.UtcNow + AckGrace;
            while (Volatile.Read(ref punchesHeard) == 0 && Volatile.Read(ref peerDone) == 0
                   && DateTimeOffset.UtcNow < cap && !ct.IsCancellationRequested)
            {
                try { await Task.Delay(TimeSpan.FromMilliseconds(25), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
            // 冗余只在"确实回过 Ack"这一路上补。等满上限那一路已经等够久了，
            // 再叠 150ms 只会让最慢的情形比改之前还慢。
            if (Volatile.Read(ref punchesHeard) > 0 && Volatile.Read(ref peerDone) == 0)
            {
                using var early = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var redundancy = Task.Delay(AckRedundancy, early.Token);
                while (!redundancy.IsCompleted && Volatile.Read(ref peerDone) == 0)
                {
                    try { await Task.WhenAny(redundancy, Task.Delay(25, ct)).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                }
                early.Cancel();
            }
        }

        // 应答方开了诱饵：等对端表态它用的是哪一对，理由见 PeerChoiceWait。
        if (awaitPeerChoice && extras.Count > 0 && success.Task.IsCompletedSuccessfully)
        {
            var until = DateTimeOffset.UtcNow + PeerChoiceWait;
            while (Volatile.Read(ref peerDone) == 0 && DateTimeOffset.UtcNow < until
                   && !ct.IsCancellationRequested)
            {
                try { await Task.Delay(TimeSpan.FromMilliseconds(25), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        await stop.CancelAsync().ConfigureAwait(false);
        foreach (var task in receivers) { try { await task.ConfigureAwait(false); } catch { } }

        var won = success.Task.IsCompletedSuccessfully ? success.Task.Result : default;
        if (Volatile.Read(ref overrideWinner) is { } corrected
            && (!corrected.Item1.Equals(won.Peer) || !ReferenceEquals(corrected.Item2, won.Via)))
        {
            log?.Invoke($"对端的压测请求来自 {corrected.Item1}，以它为准（Ack 记下的是 {won.Peer}）");
            won = (corrected.Item1, corrected.Item2);
        }
        var peer = success.Task.IsCompletedSuccessfully ? won.Peer : null;
        var winner = success.Task.IsCompletedSuccessfully ? won.Via : null;

        var elapsed = DateTimeOffset.UtcNow - started;

        // 收到 Ack 是最强证据，但不是唯一证据。
        //
        // 实测撞到过两侧判定不一致：对方的探路包到了我们这里（HMAC 验过），我们按协议
        // 回了 Ack，对方收到 Ack 判定成功；而我们自己发出去的探路包因为对方报上来的
        // 地址对我们不成立、始终没拿到 Ack，于是判定失败、没有启动监听。结果对方以为
        // 通了，连过来却没人在听，白等一整个握手超时。
        //
        // 收到一个验证通过的探路包，本身就证明了「对方能到达我们」；而我们回 Ack 时
        // 用的是观测到的真实源地址，那条路径上的 NAT 映射已经因此打开。这就足够继续
        // 往下走了。宁可多起一次监听（对方不来，20 秒后自己收摊），也不能让明明打通
        // 的链路因为判据写窄而作废。
        if (peer is null && heardFrom.Count > 0)
        {
            var observed = heardFrom.Values.First();
            peer = observed.Peer;
            winner = observed.Via;
            log?.Invoke($"未收到 Ack，但收到对方 {punchesHeard} 个探路包，按观测到的地址 {peer} 继续");
        }

        if (peer is not null)
            log?.Invoke($"打洞成功 {peer}，用时 {elapsed.TotalMilliseconds:0} ms，发出 {sent} 个包");
        else
            log?.Invoke($"打洞失败：发出 {sent} 个包，收到对方有效探路包 {punchesHeard} 个"
                    + (strangers > 0
                        ? $"；另有 {strangers} 个包到达但校验不通过——两边密钥或会话号对不上，这是代码问题不是网络问题"
                        : "；期间一个包都没到达，链路层就被挡住了"));

        // 兜底：认出了对端却没记住是哪个 socket（理论上不会走到），就按主 socket 算。
        // 宁可用主 socket 的端口试一次，也不要返回 null 让上层拿不到端口。
        if (peer is not null) winner ??= socket;

        // 没赢的诱饵全部收掉。必须在 winner 定下来之后再收——兜底路径可能把 winner
        // 指到某个诱饵上，先收就把刚打通的那个洞关了。
        foreach (var decoy in extras)
            if (!ReferenceEquals(decoy, winner))
                try { decoy.Close(); } catch { }

        var pendingLoad = Volatile.Read(ref peerDone) != 0
            ? (ulong?)(ulong)Interlocked.Read(ref peerLoadRequest)
            : null;
        return new Outcome(
            peer, elapsed, sent, punchesHeard,
            heardFrom.Values.Select(x => x.Peer).ToList(), winner, pendingLoad,
            Volatile.Read(ref peerFinished) != 0);
    }

    /// <summary>发一个探路包，登记 nonce 好认回来的 Ack。发失败当没发过。</summary>
    private static async Task<int> SendPunchAsync(
        Socket socket, IPEndPoint target, ulong session, byte[] secret,
        ConcurrentDictionary<ulong, byte> outstanding, CancellationToken ct)
    {
        var nonce = (ulong)Random.Shared.NextInt64();
        outstanding[nonce] = 0;
        try
        {
            var punch = PunchProtocol.Build(PunchProtocol.Kind.Punch, session, nonce, secret);
            await socket.SendToAsync(punch, SocketFlags.None, target, ct).ConfigureAwait(false);
            return 1;
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException) { return 0; }
    }

    /// <summary>
    /// 通路建立后定期发保活，维持 NAT 映射。运营商 NAT 的 UDP 映射老化时间通常
    /// 只有几十秒，停发就会被回收，之后对方再发过来就进不来了。
    /// </summary>
    public static async Task KeepAliveAsync(
        Socket socket, IPEndPoint peer, ulong session, byte[] secret,
        TimeSpan interval, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var packet = PunchProtocol.Build(
                    PunchProtocol.Kind.Keepalive, session, (ulong)Random.Shared.NextInt64(), secret);
                await socket.SendToAsync(packet, SocketFlags.None, peer, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException) { }
            try { await Task.Delay(interval, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }
}
