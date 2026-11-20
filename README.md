# muxi-p2p-agent

muxi-p2p 的 .NET 部分：把一台机器上的本地 TCP 服务接到另一台机器上，按顺序尝试 IPv6 直连、
路由器端口映射（UPnP/PCP）、UDP 打洞 + QUIC、TCP 打洞，最后走中转。

总仓是 [muxi-p2p](https://github.com/muxigame/muxi-p2p)，它把本仓和信令仓
[muxi-p2p-signaling](https://github.com/muxigame/muxi-p2p-signaling) 作为 submodule 挂在一起。
只需要端侧代码的项目直接引用本仓。

| 项目 | 作用 |
|---|---|
| `src/MuxiP2P.Protocol` | 协议库：NAT 探测（`MUXI-REFLECT/1`）、UDP/TCP 打洞、QUIC 隧道（System.Net.Quic / msquic）、多路复用、端口映射、线路候选 |
| `src/MuxiP2P.Client` | 连接端：向信令要候选、按线路优先级建链（`P2PTunnel`、`TunnelClient`、`TunnelProbe`） |
| `src/MuxiP2P.Agent` | 被连端 `muxi-p2p-agent`：监听隧道端口，把每条流接到本机目标端口；向信令上报候选、响应打洞 |

连接端（启动器、桌面客户端）`ProjectReference` 到 `src/MuxiP2P.Client`，会自动带上协议库。

## 构建

```bash
dotnet publish src/MuxiP2P.Agent/MuxiP2P.Agent.csproj -c Release -r linux-x64 -o out/linux-x64
dotnet publish src/MuxiP2P.Agent/MuxiP2P.Agent.csproj -c Release -r win-x64 -o out/win-x64
```

需要 .NET 9 SDK。QUIC 在 Windows 11 / Server 2022 上使用系统自带的 msquic；Linux 需要
`libmsquic`（Microsoft 软件源，或由宿主程序随包提供）。

## Agent 参数

```
muxi-p2p-agent --port <隧道监听端口> --target 127.0.0.1:<本机目标端口> --token <密钥>
               [--control-plane <信令地址> --server-id <id> --reflector <反射器主机,...>]
```

`--token`（或 `MUXI_TUNNEL_TOKEN`）是这台 agent 和信令之间的 HMAC 密钥，连接端用的 token 由
信令从它派生。没有内置的反射器地址：不配 `--reflector`（或 `MUXI_REFLECTOR`）时不打洞。

## 来源

从 `better-mc-remake`（启动器与端侧隧道工具）拆出，经 muxi-p2p（`86f9c17`）分到本仓；文件
来源与拆分时的哈希见总仓的 `SOURCE-PROVENANCE.json`。

Apache-2.0，见 [`LICENSE`](LICENSE)。
