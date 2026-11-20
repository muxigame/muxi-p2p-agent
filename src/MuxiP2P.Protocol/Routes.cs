using System.Text.Json.Serialization;

namespace BatterMC.Protocol;

// Extracted from client/protocol/Manifest.cs (route candidates only; see SOURCE-PROVENANCE.json).

/// <summary>候选线路类型。数值顺序也是默认偏好顺序。</summary>
[JsonConverter(typeof(JsonStringEnumConverter<RouteKind>))]
public enum RouteKind
{
    Auto = 0,
    LanDirect = 10,
    Ipv6Direct = 20,
    Ipv4Direct = 30,
    PortMapped = 40,
    UdpTunnel = 50,
    TcpTunnel = 60,
    Relay = 70,
}

/// <summary>
/// 由控制面或静态清单下发的一个可连接入口。本版数据面支持 TCP；UdpTunnel/QUIC
/// 类型预留给后续加密隧道 sidecar，不能被当前 TCP 代理误当成裸 MC 端口。
/// </summary>
public sealed class RouteCandidate
{
    public string Id { get; set; } = "";
    public string? Label { get; set; }
    public RouteKind Kind { get; set; } = RouteKind.Auto;
    public string Transport { get; set; } = "tcp";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 25565;
    /// <summary>同类型内的人工优先级，越小越优先。</summary>
    public int Priority { get; set; }
    /// <summary>单次 TCP 握手探测超时；0 使用客户端默认值。</summary>
    public int ProbeTimeoutMs { get; set; }
}

