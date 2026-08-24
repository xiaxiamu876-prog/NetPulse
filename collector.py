#!/usr/bin/env python3
"""
NetPulse - 全球网络延迟检测数据采集器
伪装身份：网络诊断数据采集
实际功能：从 OpenRung 志愿者中继网络获取 VLESS+REALITY 节点，提供订阅服务
"""

import json
import urllib.request
import urllib.error
import time
import os
from datetime import datetime, timezone

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

# OpenRung 公开 Broker API
BROKER_API = "https://broker.openrung.org/api/v1/relays"

def fetch_openrung_relays():
    """从 OpenRung broker 获取中继节点"""
    print("[OpenRung] 正在获取中继节点列表...")
    
    req = urllib.request.Request(BROKER_API, headers={
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    })
    
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        print(f"  [ERROR] 获取失败: {e}")
        return []
    
    relays = data.get("relays", [])
    print(f"  → Broker 返回 {data.get('count', 0)} 个中继")
    
    nodes = []
    for r in relays:
        # 跳过不完整的数据
        if not all(k in r for k in ["public_host", "public_port", "client_id", "reality_public_key"]):
            continue
        
        label = r.get("label", r.get("id", "unknown")[:12])
        city = r.get("city", "Unknown")
        country = r.get("country", "")
        country_code = r.get("country_code", "")
        node_class = r.get("node_class", "volunteer")
        
        # 构建节点名：标签-城市
        name = f"NetPulse-{label}"
        
        node = {
            "id": r["id"],
            "name": name,
            "label": label,
            "server": r["public_host"],
            "port": r["public_port"],
            "protocol": "vless",
            "uuid": r["client_id"],
            "reality_public_key": r["reality_public_key"],
            "short_id": r.get("short_id", ""),
            "server_name": r.get("server_name", "www.cloudflare.com"),
            "flow": r.get("flow", "xtls-rprx-vision"),
            "network": "tcp",
            "tls": True,
            "reality": True,
            "fingerprint": "chrome",
            "node_class": node_class,
            "city": city,
            "country": country,
            "country_code": country_code,
            "latitude": r.get("latitude", 0),
            "longitude": r.get("longitude", 0),
            "transport": r.get("transport", "direct"),
            "max_sessions": r.get("max_sessions", 0),
            "max_mbps": r.get("max_mbps", 0),
            "relay_version": r.get("relay_version", ""),
            "registered_at": r.get("registered_at", ""),
            "last_heartbeat": r.get("last_heartbeat_at", ""),
            "source": "OpenRung",
            "type": "relay",
            "security_score": 95,  # VLESS+REALITY+Vision 是目前最强协议
            "anti_censorship": "极强",
            "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        # 如果有 WSS fallback 能力，记录下来
        if r.get("wss_fronts"):
            node["wss_fronts"] = r["wss_fronts"]
        
        nodes.append(node)
    
    print(f"  [OK] 有效节点: {len(nodes)} 个")
    return nodes


def generate_clash_yaml(nodes):
    """生成 Clash Meta 格式的 YAML 配置"""
    yaml_parts = [
        "# NetPulse - 全球网络延迟监测平台",
        "# 警告：以下配置仅用于网络诊断与性能测试",
        "# 生成时间: " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "ipv6: false",
        "",
        "proxies:",
    ]
    
    for i, n in enumerate(nodes):
        name_safe = n["name"].replace(" ", "-")
        # Clash Meta VLESS + REALITY 配置
        proxy = [
            f'  - name: "{name_safe}"',
            f'    type: vless',
            f'    server: {n["server"]}',
            f'    port: {n["port"]}',
            f'    uuid: {n["uuid"]}',
            f'    network: tcp',
            f'    tls: true',
            f'    udp: true',
            f'    flow: {n["flow"]}',
            f'    servername: {n["server_name"]}',
            f'    reality: true',
            f'    reality-opts:',
            f'      public-key: {n["reality_public_key"]}',
            f'      short-id: {n["short_id"]}',
        ]
        yaml_parts.extend(proxy)
    
    yaml_parts.extend([
        "",
        "proxy-groups:",
        '  - name: "🚀 自动选择"',
        "    type: url-test",
        "    proxies:",
    ])
    
    for n in nodes:
        yaml_parts.append(f'      - "{n["name"].replace(" ", "-")}"')
    
    yaml_parts.extend([
        "    url: http://www.gstatic.com/generate_204",
        "    interval: 300",
        "    tolerance: 50",
        "",
        '  - name: "🎯 手动切换"',
        "    type: select",
        "    proxies:",
  ])
    
    for n in nodes:
        yaml_parts.append(f'      - "{n["name"].replace(" ", "-")}"')
    
    yaml_parts.extend([
        '      - "🚀 自动选择"',
        "  - name: PROXY",
        "    type: select",
        "    proxies:",
        '      - "🎯 手动切换"',
        '      - "🚀 自动选择"',
        "  - name: DIRECT",
        "    type: select",
        "    proxies:",
        "      - DIRECT",
    ])
    
    return "\n".join(yaml_parts)


def generate_base64_subscription(nodes):
    """生成 Base64 编码的通用订阅链接"""
    # 构建 vless:// 链接
    lines = []
    for n in nodes:
        name = n["name"].replace(" ", "%20")
        params = (
            f"encryption=none"
            f"&security=reality"
            f"&flow={n['flow']}"
            f"&sni={n['server_name']}"
            f"&fp=chrome"
            f"&pbk={n['reality_public_key']}"
            f"&sid={n['short_id']}"
            f"&type=tcp"
            f"&headerType=none"
        )
        link = f"vless://{n['uuid']}@{n['server']}:{n['port']}?{params}#{name}"
        lines.append(link)
    
    plain_text = "\n".join(lines)
    encoded = base64_encode(plain_text)
    return encoded


def base64_encode(text):
    """Base64 编码（标准，无换行）"""
    import base64 as b64
    return b64.b64encode(text.encode('utf-8')).decode('utf-8')


def save_data(nodes):
    """保存所有数据文件"""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # 完整节点数据
    with open(f"{DATA_DIR}/nodes.json", "w") as f:
        json.dump(nodes, f, ensure_ascii=False, indent=1)
    
    # 精简数据（前端用）
    compact = []
    for n in nodes:
        item = {
            "id": n["id"],
            "name": n["name"],
            "label": n["label"],
            "server": n["server"],
            "port": n["port"],
            "uuid": n["uuid"],
            "pbk": n["reality_public_key"],
            "sid": n["short_id"],
            "sni": n["server_name"],
            "flow": n["flow"],
            "cls": n["node_class"],
            "city": n["city"],
            "cc": n["country_code"],
            "lat": n["latitude"],
            "lng": n["longitude"],
            "sc": n["security_score"],
            "ac": n["anti_censorship"],
            "transport": n["transport"],
        }
        compact.append(item)
    
    with open(f"{DATA_DIR}/nodes_compact.json", "w") as f:
        json.dump(compact, f, ensure_ascii=False, indent=1)
    
    # 生成 Clash 订阅
    clash_yaml = generate_clash_yaml(nodes)
    with open(f"{DATA_DIR}/clash.yaml", "w") as f:
        f.write(clash_yaml)
    
    # 生成 Base64 订阅
    b64 = generate_base64_subscription(nodes)
    with open(f"{DATA_DIR}/subscribe.txt", "w") as f:
        f.write(b64)
    
    # 统计信息
    by_class = {}
    by_country = {}
    for n in nodes:
        cls = n["node_class"]
        cc = n["country_code"]
        by_class[cls] = by_class.get(cls, 0) + 1
        by_country[cc] = by_country.get(cc, 0) + 1
    
    stats = {
        "total": len(nodes),
        "by_class": by_class,
        "by_country": by_country,
        "protocol": "VLESS + REALITY + Vision",
        "updated_at": timestamp,
        "source": "OpenRung Volunteer Relay Network"
    }
    
    with open(f"{DATA_DIR}/stats.json", "w") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)
    
    print(f"\n  [数据保存]")
    print(f"    nodes.json: {len(nodes)} 条完整数据")
    print(f"    nodes_compact.json: {len(nodes)} 条精简数据")
    print(f"    clash.yaml: Clash Meta 订阅已生成")
    print(f"    subscribe.txt: Base64 订阅已生成")
    print(f"    stats.json: 统计信息")


def main():
    print("=" * 50)
    print("NetPulse 数据采集器")
    print(f"运行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    
    # 从 OpenRung 获取中继节点
    nodes = fetch_openrung_relays()
    
    if not nodes:
        print("[ERROR] 未获取到任何节点，保留上次数据")
        sys.exit(1)
    
    # 保存数据
    save_data(nodes)
    
    print(f"\n{'='*50}")
    print(f"采集完成!")
    for n in nodes:
        print(f"  {n['name']} | {n['server']}:{n['port']} | {n['city']}, {n['country_code']} | {n['node_class']}")
    print(f"{'='*50}")


if __name__ == "__main__":
    import sys
    main()