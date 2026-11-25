using System.Globalization;
using System.Net;
using System.Text;

namespace BatterMC.Protocol;

/// <summary>映射行为：同一个本地 socket 换个目标，公网端口变不变（RFC 4787）。</summary>
public enum NatMapping
{
    Unknown,
    /// <summary>端点无关：对谁都是同一个公网端口（NAT1/2/3）。</summary>
    EndpointIndependent,
    /// <summary>地址（端口）相关：每个目标一个新端口（NAT4，对称型）。</summary>
    AddressDependent,
}

/// <summary>过滤行为：已经开出的映射，谁发来的包能进来。</summary>
public enum NatFiltering
{
    Unknown,
    /// <summary>谁都能进（NAT1 全锥形）。</summary>
    EndpointIndependent,
    /// <summary>只要 IP 对得上（NAT2 限制锥形）。</summary>
    AddressDependent,
    /// <summary>IP 和端口都要对得上（NAT3 端口限制锥形；对称型基本也是这样）。</summary>
    AddressPortDependent,
}

/// <summary>对称型 NAT 怎么分新端口。决定对端能不能预测我们下一个映射。</summary>
public enum NatAllocation
{
    Unknown,
    /// <summary>端点无关映射，不分新端口。</summary>
    Stable,
    /// <summary>一个计数器，每个新映射 +1（附近偶尔被别人插队）。</summary>
    Sequential,
    /// <summary>
    /// 几个并行的计数器，每个新映射随机落到其中一个、那个计数器 +1。实测 实测机器 A 3 个、
    /// 实测机器 B 2 个，彼此相隔 120~133，看上去像"端口成对散落在 200 多个端口里"。
    /// </summary>
    MultiCounter,
    /// <summary>无规律（完全随机或块内随机），只能靠生日碰撞。</summary>
    Random,
}

/// <summary>对称型 NAT 的一个端口计数器：某个公网 IP 上，最近见到的最大端口。</summary>
public sealed record PortCounter(IPAddress Address, int Top)
{
    public override string ToString() => $"{Address}:{Top}";
}

/// <summary>
/// 一侧 NAT 的画像：映射、过滤、端口分配方式，以及对称型时各计数器的当前位置。
///
/// 打洞怎么打完全由两侧画像的组合决定（见 <see cref="PunchPlanner"/>），所以它要随候选
/// 一起报给对端：编成一条带 <see cref="Prefix"/> 前缀的候选字符串，控制面原样转发，
/// 老版本解析不了会自然跳过。
/// </summary>
/// <param name="Observable">本机能用反射器的观测通道（反射器支持 MUXI-REFLECT/2 和 MUXI-OBS）。</param>
public sealed record NatProfile(
    NatMapping Mapping,
    NatFiltering Filtering,
    NatAllocation Allocation,
    IReadOnlyList<PortCounter> Counters,
    bool Observable)
{
    public const string Prefix = "n:";

    public static readonly NatProfile Unknown =
        new(NatMapping.Unknown, NatFiltering.Unknown, NatAllocation.Unknown, [], false);

    public bool Symmetric => Mapping == NatMapping.AddressDependent;
    public bool Cone => Mapping == NatMapping.EndpointIndependent;

    /// <summary>对端能不能预测我们下一个新映射的端口（顺序或多计数器）。</summary>
    public bool Predictable => Allocation is NatAllocation.Sequential or NatAllocation.MultiCounter;

    /// <summary>经典叫法 NAT1~4；说不清时 0。</summary>
    public int Classic => Mapping switch
    {
        NatMapping.EndpointIndependent => Filtering switch
        {
            NatFiltering.EndpointIndependent => 1,
            NatFiltering.AddressDependent => 2,
            NatFiltering.AddressPortDependent => 3,
            _ => 0,
        },
        NatMapping.AddressDependent => 4,
        _ => 0,
    };

    public string Label
    {
        get
        {
            var name = Classic switch
            {
                1 => "NAT1 全锥形",
                2 => "NAT2 限制锥形",
                3 => "NAT3 端口限制锥形",
                4 => "NAT4 对称型",
                _ => Cone ? "锥形（过滤方式未测出）" : "类型未知",
            };
            if (!Symmetric) return name;
            return name + Allocation switch
            {
                NatAllocation.Sequential => "，端口顺序分配",
                NatAllocation.MultiCounter => $"，{Counters.Count} 个并行计数器顺序分配",
                NatAllocation.Random => "，端口无规律",
                _ => "，分配方式未知",
            };
        }
    }

    public string Describe() =>
        Label
        + (Symmetric && Counters.Count > 0 ? $"（计数器 {string.Join("，", Counters)}）" : "")
        + (Filtering == NatFiltering.Unknown || Classic is 1 or 2 or 3 ? "" : Filtering switch
        {
            NatFiltering.EndpointIndependent => "，过滤：谁都放行",
            NatFiltering.AddressDependent => "，过滤：只认 IP",
            _ => "，过滤：IP+端口都要对上",
        });

    public string ToTag()
    {
        var text = new StringBuilder(Prefix)
            .Append("m=").Append(Mapping switch
            {
                NatMapping.EndpointIndependent => 'e',
                NatMapping.AddressDependent => 'a',
                _ => 'u',
            })
            .Append(";f=").Append(Filtering switch
            {
                NatFiltering.EndpointIndependent => 'e',
                NatFiltering.AddressDependent => 'a',
                NatFiltering.AddressPortDependent => 'p',
                _ => 'u',
            })
            .Append(";a=").Append(Allocation switch
            {
                NatAllocation.Stable => 's',
                NatAllocation.Sequential => 'q',
                NatAllocation.MultiCounter => 'm',
                NatAllocation.Random => 'r',
                _ => 'u',
            })
            .Append(";o=").Append(Observable ? '1' : '0');
        if (Counters.Count > 0)
            text.Append(";c=").Append(string.Join("|", Counters
                .GroupBy(c => c.Address)
                .Select(g => g.Key + "/" + string.Join("/", g.Select(c => c.Top.ToString(CultureInfo.InvariantCulture))))));
        return text.ToString();
    }

    /// <summary>解析对端报来的画像条目；不是画像条目或格式不对时返回 false。</summary>
    public static bool TryParseTag(string candidate, out NatProfile profile)
    {
        profile = Unknown;
        if (!candidate.StartsWith(Prefix, StringComparison.Ordinal)) return false;
        var mapping = NatMapping.Unknown;
        var filtering = NatFiltering.Unknown;
        var allocation = NatAllocation.Unknown;
        var observable = false;
        var counters = new List<PortCounter>();
        foreach (var field in candidate[Prefix.Length..].Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var cut = field.IndexOf('=');
            if (cut <= 0) continue;
            var key = field[..cut];
            var value = field[(cut + 1)..];
            switch (key)
            {
                case "m":
                    mapping = value switch { "e" => NatMapping.EndpointIndependent, "a" => NatMapping.AddressDependent, _ => NatMapping.Unknown };
                    break;
                case "f":
                    filtering = value switch
                    {
                        "e" => NatFiltering.EndpointIndependent,
                        "a" => NatFiltering.AddressDependent,
                        "p" => NatFiltering.AddressPortDependent,
                        _ => NatFiltering.Unknown,
                    };
                    break;
                case "a":
                    allocation = value switch
                    {
                        "s" => NatAllocation.Stable,
                        "q" => NatAllocation.Sequential,
                        "m" => NatAllocation.MultiCounter,
                        "r" => NatAllocation.Random,
                        _ => NatAllocation.Unknown,
                    };
                    break;
                case "o":
                    observable = value == "1";
                    break;
                case "c":
                    foreach (var group in value.Split('|', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var parts = group.Split('/');
                        if (parts.Length < 2 || !IPAddress.TryParse(parts[0], out var address)) continue;
                        foreach (var port in parts.Skip(1).Take(8))
                            if (int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
                                && number is > 0 and <= 65535)
                                counters.Add(new PortCounter(address, number));
                    }
                    break;
            }
        }
        if (mapping == NatMapping.Unknown) return false;
        profile = new NatProfile(mapping, filtering, allocation, counters.Take(16).ToList(), observable);
        return true;
    }

    /// <summary>
    /// 对端没报画像（老版本）时，从它的候选里推：同一个 IP 报了多个端口就是对称型，
    /// 计数器按端口聚类取每段最大值；过滤方式和分配方式都说不清。
    /// </summary>
    public static NatProfile Infer(IReadOnlyList<IPEndPoint> candidates)
    {
        var v4 = candidates.Where(c => c.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToList();
        if (v4.Count == 0) return Unknown;
        var symmetric = v4.GroupBy(c => c.Address).Any(g => g.Select(c => c.Port).Distinct().Count() > 1);
        return symmetric
            ? new NatProfile(NatMapping.AddressDependent, NatFiltering.Unknown, NatAllocation.Unknown,
                NatClassifier.Counters(v4), false)
            : new NatProfile(NatMapping.EndpointIndependent, NatFiltering.Unknown, NatAllocation.Stable, [], false);
    }

    /// <summary>从一堆候选字符串里挑出画像条目（没有就返回 null）。</summary>
    public static NatProfile? FindTag(IEnumerable<string> candidates)
    {
        foreach (var candidate in candidates)
            if (TryParseTag(candidate, out var profile)) return profile;
        return null;
    }
}
