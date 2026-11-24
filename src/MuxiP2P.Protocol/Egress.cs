using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace BatterMC.Protocol;

/// <summary>
/// 打洞流量从哪张网卡出去，以及哪些网卡根本不该公布。
///
/// Windows 上开着 clash/mihomo 的 TUN（或 WireGuard、OpenVPN……）时，所有出站流量都被
/// 虚拟网卡接走，从 VPN 的出口（往往在海外）出去：反射器看到的是 VPN 服务器的地址，
/// 同在国内的两台机器打洞要绕地球一圈（实测 300+ ms），而且 VPN 那一层 NAT 往往打不通。
/// Windows 是强主机模型：socket 绑到物理网卡的地址上，包就从这张网卡按它自己的默认
/// 路由出去，绕开 TUN。
///
/// 所以有 VPN 时打洞的 socket 一律绑物理网卡；物理网卡上探测不到出口（这台机器只能
/// 经 VPN 出网）就回退成原来的 <see cref="IPAddress.Any"/>，一段时间后再试。
/// <c>MUXI_BIND_ADDRESS</c> 可以显式指定（填 <c>any</c> 关掉这套逻辑）。
/// Linux 不做这件事：那边按源地址选路要靠策略路由，绑地址绕不开 TUN。
/// </summary>
public static class Egress
{
    /// <summary>虚拟网卡的常见名字。公布它们的地址只会让对端白白探测，甚至连到别人那里去。</summary>
    public static readonly string[] VirtualHints =
    [
        "hyper-v", "virtual", "vmware", "virtualbox", "vethernet", "wsl", "docker",
        "tap-", "tun", "meta", "mihomo", "clash", "wintun", "zerotier", "tailscale",
        "loopback", "teredo", "isatap", "wireguard", "openvpn", "sing-box",
        // Linux：容器和虚拟机的网桥、veth、overlay——docker 的自建网络网桥叫 br-<hash>，
        // 两台都跑 docker 的机器上 172.18.0.1 这种地址必然撞车（连到自己身上）
        "br-", "veth", "virbr", "cni", "flannel", "calico", "kube", "lxc", "lxd", "podman", "vxlan",
    ];

    /// <summary>VPN 类虚拟网卡：它们在线就说明出站流量多半被接走了。</summary>
    private static readonly string[] VpnHints =
    [
        "meta", "mihomo", "clash", "wintun", "tun", "tap-", "wireguard", "openvpn", "sing-box",
        "v2ray", "xray", "zerotier", "tailscale",
    ];

    /// <summary>不该公布、也不能用来出站的网卡。</summary>
    public static bool LooksVirtual(NetworkInterface nic)
    {
        if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) return true;
        var haystack = (nic.Name + " " + nic.Description).ToLowerInvariant();
        if (VirtualHints.Any(hint => haystack.Contains(hint, StringComparison.Ordinal))) return true;
        // Linux：物理网卡（云主机的 virtio 也算）在 /sys/class/net/<名字>/device 下有设备链接，
        // 网桥、veth、tun 都没有——比按名字猜可靠得多。
        if (OperatingSystem.IsLinux() && Directory.Exists("/sys/class/net/" + nic.Name)
            && !Directory.Exists("/sys/class/net/" + nic.Name + "/device"))
            return true;
        return false;
    }

    private static readonly object Gate = new();
    private static IPAddress? _cached;
    private static DateTime _cachedAt;
    private static DateTime _physicalFailedUntil;

    /// <summary>打洞 socket 绑哪个 IPv4 地址：有 VPN 时是物理网卡，否则 <see cref="IPAddress.Any"/>。</summary>
    public static IPAddress V4
    {
        get
        {
            lock (Gate)
            {
                var now = DateTime.UtcNow;
                if (now < _physicalFailedUntil) return IPAddress.Any;
                if (_cached is null || now - _cachedAt > TimeSpan.FromMinutes(1))
                {
                    _cached = Detect(out var why);
                    _cachedAt = now;
                    if (!_cached.Equals(IPAddress.Any)) Log?.Invoke(why);
                }
                return _cached;
            }
        }
    }

    /// <summary>打洞 socket 的本地端点。</summary>
    public static IPEndPoint V4EndPoint(int port) => new(V4, port);

    /// <summary>
    /// 绑物理网卡的 socket 探测不到公网出口：这台机器只能经 VPN 出网。接下来一段时间
    /// 回退成 <see cref="IPAddress.Any"/>（走 VPN），过后再试物理网卡。
    /// </summary>
    public static void PhysicalUnreachable(TimeSpan forHowLong)
    {
        lock (Gate) _physicalFailedUntil = DateTime.UtcNow + forHowLong;
        Log?.Invoke($"物理网卡上探测不到公网出口，{forHowLong.TotalMinutes:0} 分钟内打洞改走 VPN");
    }

    /// <summary>日志出口（Protocol 层不依赖具体的日志实现）。</summary>
    public static Action<string>? Log { get; set; }

    private static IPAddress Detect(out string why)
    {
        why = "";
        var forced = Environment.GetEnvironmentVariable("MUXI_BIND_ADDRESS");
        if (!string.IsNullOrWhiteSpace(forced))
        {
            if (forced.Trim().Equals("any", StringComparison.OrdinalIgnoreCase)) return IPAddress.Any;
            if (IPAddress.TryParse(forced.Trim(), out var explicitAddress)
                && explicitAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                why = $"打洞从 MUXI_BIND_ADDRESS={explicitAddress} 发出";
                return explicitAddress;
            }
        }
        if (!OperatingSystem.IsWindows()) return IPAddress.Any;
        NetworkInterface[] nics;
        try { nics = NetworkInterface.GetAllNetworkInterfaces(); }
        catch (NetworkInformationException) { return IPAddress.Any; }

        var up = nics.Where(n => n.OperationalStatus == OperationalStatus.Up).ToArray();
        var vpn = up.FirstOrDefault(n =>
        {
            var haystack = (n.Name + " " + n.Description).ToLowerInvariant();
            return VpnHints.Any(hint => haystack.Contains(hint, StringComparison.Ordinal))
                   && n.GetIPProperties().UnicastAddresses.Any(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
        });
        if (vpn is null) return IPAddress.Any;

        // 物理网卡：在线、不是虚拟网卡、有 IPv4 默认网关。有线优先于无线。
        var physical = up
            .Where(n => !LooksVirtual(n) && n.NetworkInterfaceType is NetworkInterfaceType.Ethernet
                or NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.GigabitEthernet
                or NetworkInterfaceType.FastEthernetT or NetworkInterfaceType.FastEthernetFx)
            .Select(n => (Nic: n, Props: n.GetIPProperties()))
            .Where(x => x.Props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork
                                                           && !g.Address.Equals(IPAddress.Any)))
            .OrderBy(x => x.Nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? 1 : 0)
            .Select(x => x.Props.UnicastAddresses
                .Select(a => a.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork
                                     && !IPAddress.IsLoopback(a) && a.GetAddressBytes()[0] != 169))
            .FirstOrDefault(a => a is not null);
        if (physical is null) return IPAddress.Any;
        why = $"检测到 VPN 网卡（{vpn.Name}），打洞绕开它，从物理网卡 {physical} 发出";
        return physical;
    }

    // ---------------------------------------------------------------- HTTP：IPv6 / IPv4 同时尝试

    /// <summary>
    /// 和控制面说话用的 handler：IPv6、IPv4 同时连（IPv6 先走 250ms），谁先连上用谁。
    ///
    /// .NET 默认按 DNS 顺序一个个地址试：IPv6 那条路丢包时要等到连接超时才轮到 IPv4。
    /// 实测某家宽带到 Cloudflare 的 IPv6 偶尔要 10 秒才连上，取隧道凭据（8 秒连接超时）
    /// 就整个失败了，而 IPv4 一直只要 0.2 秒。
    /// </summary>
    public static SocketsHttpHandler HttpHandler(TimeSpan connectTimeout) => new()
    {
        PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
        ConnectTimeout = connectTimeout,
        ConnectCallback = ConnectHappyEyeballsAsync,
    };

    public static HttpClient NewHttpClient(TimeSpan timeout) =>
        new(HttpHandler(TimeSpan.FromSeconds(8))) { Timeout = timeout };

    private static readonly TimeSpan HappyEyeballsDelay = TimeSpan.FromMilliseconds(250);

    private static async ValueTask<Stream> ConnectHappyEyeballsAsync(SocketsHttpConnectionContext context,
                                                                    CancellationToken ct)
    {
        var host = context.DnsEndPoint.Host;
        var port = context.DnsEndPoint.Port;
        var addresses = IPAddress.TryParse(host, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        var v6 = addresses.Where(a => a.AddressFamily == AddressFamily.InterNetworkV6).ToList();
        var v4 = addresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList();
        // 交替排：v6, v4, v6, v4……，第一个 v4 在第一个 v6 之后 250ms 出发
        var order = new List<IPAddress>();
        for (var i = 0; i < Math.Max(v6.Count, v4.Count); i++)
        {
            if (i < v6.Count) order.Add(v6[i]);
            if (i < v4.Count) order.Add(v4[i]);
        }
        if (order.Count == 0) throw new SocketException((int)SocketError.HostNotFound);

        using var race = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var attempts = new List<Task<Socket>>();
        Exception? last = null;
        for (var i = 0; i < order.Count || attempts.Count > 0;)
        {
            if (i < order.Count)
            {
                attempts.Add(ConnectOneAsync(order[i], port, race.Token));
                i++;
            }
            var delay = i < order.Count ? Task.Delay(HappyEyeballsDelay, race.Token) : null;
            var pending = delay is null ? attempts.Cast<Task>().ToList() : [.. attempts, delay];
            var done = await Task.WhenAny(pending).ConfigureAwait(false);
            if (done == delay) continue;  // 下一个地址出发
            var attempt = (Task<Socket>)done;
            attempts.Remove(attempt);
            try
            {
                var socket = await attempt.ConfigureAwait(false);
                race.Cancel();
                foreach (var other in attempts)
                    _ = other.ContinueWith(t => { if (t.IsCompletedSuccessfully) t.Result.Dispose(); },
                        TaskScheduler.Default);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception error) when (error is SocketException or OperationCanceledException)
            {
                if (ct.IsCancellationRequested) throw;
                last = error;
            }
        }
        throw last ?? new SocketException((int)SocketError.HostUnreachable);
    }

    private static async Task<Socket> ConnectOneAsync(IPAddress address, int port, CancellationToken ct)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), ct).ConfigureAwait(false);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
