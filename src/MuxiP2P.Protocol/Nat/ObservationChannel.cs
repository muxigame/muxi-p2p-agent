using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace BatterMC.Protocol;

/// <summary>
/// 通过反射器互相看对方 NAT 计数器的实时位置（对称型对对称型打洞用）。
///
/// 这就是"B、C 公网观测点 + A 信令汇总"那套思路落在现有部署上：反射器既是观测点也是
/// 汇总点。每一侧在每轮开完新流之后，用几个**新 socket** 各朝反射器发一个探测包（新
/// socket 的映射和打洞 socket 走同一组计数器，实测确认过），nonce 里带着会话号和自己是
/// 哪一侧；反射器把看到的端口记下来。另一侧每隔 <see cref="PollInterval"/> 去问一次
/// "会话 S 的对方侧最近看到了哪些端口"，喂给 <see cref="CounterTracker"/>。
///
/// 自己这一侧的观测也一起拉，用来知道自己有几个计数器——对端每轮会给我们每个计数器
/// 各开一条流，我们反过来也一样。
/// </summary>
public sealed class ObservationChannel : IAsyncDisposable
{
    public static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(150);
    private static readonly byte[] Reflect = Encoding.ASCII.GetBytes("MUXI-REFLECT/1 ");

    private readonly IPAddress _local;
    private readonly IPEndPoint _reflector;
    private readonly ulong _session;
    private readonly char _side;
    private readonly Socket _query;
    private readonly CancellationTokenSource _stop = new();
    private Task? _loop;
    private int _seq;
    private int _peerAfter = -1;
    private int _mineAfter = -1;

    public CounterTracker Peer { get; }
    public CounterTracker Mine { get; }
    public int ProbesSent => Volatile.Read(ref _seq);
    public int Replies { get; private set; }

    public char PeerSide => _side == 'c' ? 'a' : 'c';

    public ObservationChannel(IPAddress local, IPEndPoint reflector, ulong session, char side,
        IEnumerable<PortCounter> peerInitial, IEnumerable<PortCounter> mineInitial)
    {
        _local = local;
        _reflector = reflector;
        _session = session;
        _side = side;
        Peer = new CounterTracker(peerInitial);
        Mine = new CounterTracker(mineInitial);
        _query = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _query.Bind(new IPEndPoint(local, 0));
        FilteringProbe.SilenceIcmpResets(_query);
    }

    public void Start(CancellationToken ct)
    {
        var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _stop.Token);
        _loop = Task.WhenAll(PollAsync(linked.Token), ReceiveAsync(linked.Token));
    }

    /// <summary>
    /// 发 <paramref name="count"/> 个探测：每个一个新 socket、一个新映射。发完就关，不等回包——
    /// 结果走反射器的观测存储，由轮询拿回来。
    /// </summary>
    public async Task ProbeAsync(int count, CancellationToken ct)
    {
        for (var i = 0; i < count && !ct.IsCancellationRequested; i++)
        {
            var seq = Interlocked.Increment(ref _seq);
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                probe.Bind(new IPEndPoint(_local, 0));
                var payload = Reflect.Concat(Encoding.ASCII.GetBytes($"o.{_session:x16}.{_side}.{seq}")).ToArray();
                // 发两遍：探测只有这一个包，丢了对方就少一个观测（实测 实测机器 A 那条线 5 个丢 1 个）。
                // 同一个 socket、同一个目标，不会多开映射；反射器按序号去重。
                await probe.SendToAsync(payload, SocketFlags.None, _reflector, ct).ConfigureAwait(false);
                await probe.SendToAsync(payload, SocketFlags.None, _reflector, ct).ConfigureAwait(false);
            }
            catch (SocketException) { }
            catch (OperationCanceledException) { return; }
        }
    }

    private async Task PollAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            foreach (var (side, after) in new[] { (PeerSide, Volatile.Read(ref _peerAfter)), (_side, Volatile.Read(ref _mineAfter)) })
            {
                var payload = Encoding.ASCII.GetBytes($"MUXI-OBS/1 {_session:x16} {side} {after}");
                try { await _query.SendToAsync(payload, SocketFlags.None, _reflector, ct).ConfigureAwait(false); }
                catch (SocketException) { }
                catch (OperationCanceledException) { return; }
                catch (ObjectDisposedException) { return; }
            }
            try { await Task.Delay(PollInterval, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    private async Task ReceiveAsync(CancellationToken ct)
    {
        var buffer = new byte[8192];
        while (!ct.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await _query.ReceiveFromAsync(buffer, SocketFlags.None,
                    new IPEndPoint(IPAddress.Any, 0), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { continue; }
            try { Absorb(buffer.AsSpan(0, received.ReceivedBytes)); }
            catch (Exception error) when (error is JsonException or InvalidOperationException or FormatException) { }
        }
    }

    private void Absorb(ReadOnlySpan<byte> data)
    {
        using var document = JsonDocument.Parse(data.ToArray());
        var root = document.RootElement;
        if (!root.TryGetProperty("side", out var sideText) || sideText.GetString() is not { Length: 1 } side) return;
        if (!root.TryGetProperty("obs", out var list) || list.ValueKind != JsonValueKind.Array) return;
        Replies++;
        var tracker = side[0] == _side ? Mine : Peer;
        foreach (var row in list.EnumerateArray())
        {
            if (row.ValueKind != JsonValueKind.Array || row.GetArrayLength() < 4) continue;
            var seq = row[0].GetInt32();
            if (!IPAddress.TryParse(row[1].GetString(), out var address)) continue;
            var port = row[2].GetInt32();
            if (port is <= 0 or > 65535) continue;
            ref var after = ref side[0] == _side ? ref _mineAfter : ref _peerAfter;
            if (seq <= Volatile.Read(ref after)) continue;
            Volatile.Write(ref after, seq);
            var age = TimeSpan.FromMilliseconds(Math.Max(0, row[3].GetInt32()));
            tracker.Observe(address, port, DateTimeOffset.UtcNow - age);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        try { _query.Close(); } catch { }
        if (_loop is not null)
        {
            try { await _loop.ConfigureAwait(false); } catch { }
        }
        _stop.Dispose();
    }
}
