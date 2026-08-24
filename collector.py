#!/usr/bin/env python3
"""
NetPulse - 全球网络延迟检测数据采集器
伪装身份：网络诊断数据采集
实际功能：聚合 VPN Gate 志愿者节点和 GitHub 开源代理节点
"""

import json
import csv
import base64
import hashlib
import re
import time
import os
import sys
import urllib.request
import urllib.error
import socket
from datetime import datetime, timezone

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

# ===== 数据源配置 =====

SOURCES = {
    "vpngate": {
        "url": "https://www.vpngate.net/api/iphone/",
        "type": "vpngate",
        "max_nodes": 200,
        "timeout": 30
    },
    "vpngate_mirror": {
        "url": "http://219.255.212.214:27095/api/iphone/",
        "type": "vpngate",
        "max_nodes": 200,
        "timeout": 15
    },
    "github_gfpcom_http": {
        "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/http.txt",
        "type": "http",
        "max_nodes": 300,
        "timeout": 15
    },
    "github_gfpcom_socks5": {
        "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks5.txt",
        "type": "socks5",
        "max_nodes": 300,
        "timeout": 15
    },
    "github_gfpcom_socks4": {
        "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks4.txt",
        "type": "socks4",
        "max_nodes": 200,
        "timeout": 15
    },
    "github_gfpcom_vmess": {
        "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vmess.txt",
        "type": "vmess",
        "max_nodes": 200,
        "timeout": 15
    },
    "github_gfpcom_trojan": {
        "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/trojan.txt",
        "type": "trojan",
        "max_nodes": 200,
        "timeout": 15
    },
    "github_gfpcom_ss": {
        "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/ss.txt",
        "type": "ss",
        "max_nodes": 200,
        "timeout": 15
    },
    "github_gfpcom_vless": {
        "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt",
        "type": "vless",
        "max_nodes": 200,
        "timeout": 15
    },
    "github_monosans": {
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies.json",
        "type": "json_all",
        "max_nodes": 300,
        "timeout": 15
    },
    "github_jetkai": {
        "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online/proxies.json",
        "type": "json_all",
        "max_nodes": 200,
        "timeout": 15
    }
}

# ===== 工具函数 =====

def fetch_url(url, timeout=15):
    """获取 URL 内容"""
    req = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='replace')
    except Exception as e:
        print(f"  [WARN] 获取失败: {e}")
        return None

def node_id(ip, port, protocol):
    """生成节点唯一 ID"""
    raw = f"{ip}:{port}:{protocol}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]

def ping_test(ip, timeout=3):
    """模拟 ping 检测（连接测试）"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.time()
        sock.connect((ip, 80))
        elapsed = int((time.time() - start) * 1000)
        sock.close()
        return elapsed, "online"
    except:
        return None, "offline"

def classify_anti_censorship(protocol, config_data=None):
    """
    抗干扰等级分类
    - 极强: Reality, Hysteria2, TUIC
    - 强: TLS(VMess+TLS, Trojan, VLESS+TLS), WS+TLS
    - 普通: HTTP, SOCKS, 无加密
    """
    protocol_lower = protocol.lower()
    
    if any(x in protocol_lower for x in ['reality', 'hysteria2', 'hy2', 'tuic']):
        return "极强"
    if any(x in protocol_lower for x in ['trojan', 'tls', 'https', 'vmess+tls', 'vless+tls', 'ws+tls']):
        return "强"
    if any(x in protocol_lower for x in ['ss', 'shadowsocks', 'vmess', 'vless', 'ws', 'grpc']):
        return "强"
    return "普通"

def security_score(protocol, source):
    """安全评分 (0-100)"""
    score = 50
    protocol_lower = protocol.lower()
    
    # 加密协议加分
    if any(x in protocol_lower for x in ['reality', 'trojan', 'tls', 'ss', 'shadowsocks', 'hy2', 'hysteria', 'tuic', 'wireguard']):
        score += 30
    if any(x in protocol_lower for x in ['vmess', 'vless', 'https']):
        score += 15
    
    # 来源加分
    if 'vpngate' in source.lower():
        score += 10  # 学术来源
    if 'github' in source.lower():
        score += 5
    
    # HTTP 减分
    if protocol_lower in ['http', 'https']:
        score -= 10
    
    score = max(0, min(100, score))
    return score

# ===== VPN Gate 采集 =====

def parse_vpngate_csv(text):
    """解析 VPN Gate CSV 格式"""
    nodes = []
    lines = text.strip().split('\n')
    
    # VPN Gate CSV 格式：前两行是注释，第三行开始是数据
    # 列: #HostName,IP,Port,Network,Ping,Keyword,Country,CountryCode,...
    # 实际上 VPN Gate 的 CSV 格式很特殊，第一行是 *
    # 第二行是列名，第三行开始是数据
    
    data_lines = []
    started = False
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith('*'):
            continue
        if not started:
            started = True
            continue  # 跳过列名行
        data_lines.append(line)
    
    for line in data_lines:
        try:
            # VPN Gate CSV 用逗号分隔，但 OpenVPN 配置在最后一列包含逗号
            # 所以只取前几列
            parts = line.split(',')
            if len(parts) < 7:
                continue
            
            hostname = parts[0].strip()
            ip = parts[1].strip()
            port = parts[2].strip()
            network_type = parts[3].strip()  # TCP/UDP
            ping_str = parts[4].strip()
            speed_str = parts[5].strip() if len(parts) > 5 else "0"
            country = parts[6].strip() if len(parts) > 6 else ""
            
            if not ip or not port:
                continue
            
            # 解码 OpenVPN 配置（如果存在）
            ovpn_b64 = ""
            if len(parts) > 14:
                ovpn_b64 = parts[14].strip()
            
            try:
                ping = int(ping_str) if ping_str and ping_str.isdigit() else 999
            except:
                ping = 999
            
            try:
                speed = int(speed_str) if speed_str and speed_str.isdigit() else 0
            except:
                speed = 0
            
            node = {
                "id": node_id(ip, port, "openvpn"),
                "ip": ip,
                "port": int(port) if port.isdigit() else 0,
                "protocol": "openvpn",
                "type": "vpngate",
                "country": country,
                "hostname": hostname,
                "ping": ping,
                "speed": speed,
                "network": network_type,
                "source": "VPN Gate",
                "anti_censorship": "强",
                "security_score": security_score("openvpn", "VPN Gate"),
                "is_residential": True,
                "ovpn_config": ovpn_b64,
                "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
            nodes.append(node)
        except:
            continue
    
    return nodes

def fetch_vpngate():
    """采集 VPN Gate 节点"""
    print("[VPN Gate] 正在采集住宅 IP 节点...")
    all_nodes = []
    
    for source_name, config in SOURCES.items():
        if config["type"] != "vpngate":
            continue
        
        print(f"  尝试 {source_name}: {config['url']}")
        text = fetch_url(config["url"], config["timeout"])
        if not text:
            continue
        
        nodes = parse_vpngate_csv(text)
        print(f"  → 获取 {len(nodes)} 个节点")
        
        # 限制数量
        max_n = config["max_nodes"]
        nodes = nodes[:max_n]
        for n in nodes:
            n["source_name"] = source_name
        
        all_nodes.extend(nodes)
        break  # 只用一个来源
    
    # 去重
    seen = set()
    unique = []
    for n in all_nodes:
        key = f"{n['ip']}:{n['port']}"
        if key not in seen:
            seen.add(key)
            unique.append(n)
    
    print(f"  [OK] VPN Gate: {len(unique)} 个住宅 IP 节点")
    return unique

# ===== GitHub 代理源采集 =====

def parse_github_proxy(text, source_type, source_name, max_nodes):
    """解析 GitHub 代理列表"""
    nodes = []
    
    if source_type == "json_all":
        try:
            data = json.loads(text)
            for item in data[:max_nodes]:
                ip = item.get("ip") or item.get("host") or ""
                port = item.get("port") or 0
                protocol = item.get("protocol") or item.get("type") or "http"
                country = item.get("country") or item.get("geo") or ""
                ping = item.get("ping") or item.get("responseTime") or 999
                
                if not ip or not port:
                    continue
                
                nid = node_id(ip, port, protocol)
                nodes.append({
                    "id": nid,
                    "ip": ip,
                    "port": int(port),
                    "protocol": protocol.lower(),
                    "type": "proxy",
                    "country": country,
                    "ping": int(ping) if str(ping).isdigit() else 999,
                    "source": source_name,
                    "anti_censorship": classify_anti_censorship(protocol),
                    "security_score": security_score(protocol, source_name),
                    "is_residential": False,
                    "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                })
        except:
            pass
    
    elif source_type in ["http", "socks5", "socks4"]:
        for line in text.strip().split('\n')[:max_nodes]:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) >= 2:
                ip = parts[0].strip()
                port = parts[1].strip().split()[0]  # 可能有额外信息
                if ip and port.isdigit():
                    nid = node_id(ip, port, source_type)
                    nodes.append({
                        "id": nid,
                        "ip": ip,
                        "port": int(port),
                        "protocol": source_type,
                        "type": "proxy",
                        "country": "",
                        "ping": 999,
                        "source": source_name,
                        "anti_censorship": "普通",
                        "security_score": security_score(source_type, source_name),
                        "is_residential": False,
                        "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    })
    
    elif source_type in ["vmess", "trojan", "ss", "vless"]:
        for line in text.strip().split('\n')[:max_nodes]:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # 尝试解析链接格式
            try:
                if source_type == "vmess" and line.startswith("vmess://"):
                    decoded = base64.b64decode(line[8:].split('#')[0].strip()).decode('utf-8', errors='replace')
                    config = json.loads(decoded)
                    ip = config.get("add", "")
                    port = config.get("port", 0)
                    nid = node_id(ip, port, "vmess")
                    nodes.append({
                        "id": nid, "ip": ip, "port": int(port),
                        "protocol": "vmess", "type": "proxy",
                        "country": "", "ping": 999,
                        "source": source_name,
                        "anti_censorship": "强",
                        "security_score": security_score("vmess", source_name),
                        "is_residential": False,
                        "config_link": line.strip(),
                        "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    })
                elif source_type == "trojan" and line.startswith("trojan://"):
                    parts = line.strip().split('@')
                    if len(parts) >= 2:
                        host_port = parts[1].split('#')[0].split('/')[0].split(':')
                        ip = host_port[0]
                        port = int(host_port[1]) if len(host_port) > 1 and host_port[1].isdigit() else 443
                        nid = node_id(ip, port, "trojan")
                        nodes.append({
                            "id": nid, "ip": ip, "port": port,
                            "protocol": "trojan", "type": "proxy",
                            "country": "", "ping": 999,
                            "source": source_name,
                            "anti_censorship": "强",
                            "security_score": security_score("trojan", source_name),
                            "is_residential": False,
                            "config_link": line.strip(),
                            "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        })
                elif source_type == "ss" and line.startswith("ss://"):
                    parts = line.strip().split('#')
                    nid = node_id(parts[0], hash(parts[0]) % 65535, "ss")
                    nodes.append({
                        "id": nid, "ip": "extracted", "port": 0,
                        "protocol": "shadowsocks", "type": "proxy",
                        "country": "", "ping": 999,
                        "source": source_name,
                        "anti_censorship": "强",
                        "security_score": security_score("ss", source_name),
                        "is_residential": False,
                        "config_link": line.strip(),
                        "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    })
                elif source_type == "vless" and line.startswith("vless://"):
                    parts = line.strip().split('@')
                    if len(parts) >= 2:
                        host_port = parts[1].split('#')[0].split('/')[0].split(':')
                        ip = host_port[0] if len(host_port) > 0 else ""
                        port = int(host_port[1]) if len(host_port) > 1 and host_port[1].isdigit() else 443
                        nid = node_id(ip, port, "vless")
                        nodes.append({
                            "id": nid, "ip": ip, "port": port,
                            "protocol": "vless", "type": "proxy",
                            "country": "", "ping": 999,
                            "source": source_name,
                            "anti_censorship": "极强",
                            "security_score": security_score("vless", source_name),
                            "is_residential": False,
                            "config_link": line.strip(),
                            "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        })
            except:
                continue
    
    return nodes

def fetch_github_sources():
    """采集所有 GitHub 代理源"""
    print("[GitHub] 正在采集开源代理节点...")
    all_nodes = []
    
    for source_name, config in SOURCES.items():
        if config["type"] == "vpngate":
            continue
        
        print(f"  [{source_name}] {config['url']}")
        text = fetch_url(config["url"], config["timeout"])
        if not text:
            continue
        
        nodes = parse_github_proxy(text, config["type"], source_name, config["max_nodes"])
        print(f"  → {len(nodes)} 个节点")
        all_nodes.extend(nodes)
    
    # 去重
    seen = set()
    unique = []
    for n in all_nodes:
        key = f"{n['ip']}:{n['port']}:{n['protocol']}"
        if key not in seen:
            seen.add(key)
            unique.append(n)
    
    print(f"  [OK] GitHub 源: {len(unique)} 个节点")
    return unique

# ===== 数据合并与统计 =====

def merge_nodes(vpngate_nodes, github_nodes):
    """合并两源数据"""
    all_nodes = vpngate_nodes + github_nodes
    
    # 按协议分类统计
    stats = {
        "total": len(all_nodes),
        "residential": len([n for n in all_nodes if n.get("is_residential")]),
        "datacenter": len([n for n in all_nodes if not n.get("is_residential")]),
        "by_protocol": {},
        "by_anti_censorship": {},
        "by_country": {},
        "vpn_gate": len(vpngate_nodes)
    }
    
    for n in all_nodes:
        proto = n["protocol"]
        ac = n["anti_censorship"]
        country = n.get("country", "Unknown")[:2] if n.get("country") else "??"
        
        stats["by_protocol"][proto] = stats["by_protocol"].get(proto, 0) + 1
        stats["by_anti_censorship"][ac] = stats["by_anti_censorship"].get(ac, 0) + 1
        stats["by_country"][country] = stats["by_country"].get(country, 0) + 1
    
    return all_nodes, stats

def save_data(nodes, stats):
    """保存数据文件"""
    # 完整数据
    with open(f"{DATA_DIR}/nodes.json", "w") as f:
        json.dump(nodes, f, ensure_ascii=False, indent=1)
    
    # 精简数据（前端用，去掉大字段）
    compact = []
    for n in nodes:
        item = {
            "id": n["id"],
            "ip": n["ip"],
            "port": n["port"],
            "p": n["protocol"],
            "t": n.get("type", ""),
            "c": n.get("country", ""),
            "g": n.get("ping", 999),
            "s": n.get("security_score", 50),
            "ac": n.get("anti_censorship", "普通"),
            "rs": n.get("is_residential", False),
            "src": n.get("source", ""),
            "sp": n.get("speed", 0)
        }
        if n.get("config_link"):
            item["cl"] = n["config_link"]
        if n.get("ovpn_config"):
            item["ov"] = n["ovpn_config"]
        compact.append(item)
    
    with open(f"{DATA_DIR}/nodes_compact.json", "w") as f:
        json.dump(compact, f, ensure_ascii=False, indent=1)
    
    # 统计信息
    stats["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(f"{DATA_DIR}/stats.json", "w") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)
    
    print(f"\n  [数据保存]")
    print(f"    nodes.json: {len(nodes)} 条完整数据")
    print(f"    nodes_compact.json: {len(compact)} 条精简数据")
    print(f"    stats.json: 统计信息")

# ===== 主流程 =====

def main():
    print("=" * 50)
    print("NetPulse 数据采集器")
    print(f"运行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    
    # 采集 VPN Gate
    vpngate_nodes = fetch_vpngate()
    
    # 采集 GitHub 源
    github_nodes = fetch_github_sources()
    
    # 合并
    all_nodes, stats = merge_nodes(vpngate_nodes, github_nodes)
    
    # 保存
    save_data(all_nodes, stats)
    
    print(f"\n{'='*50}")
    print(f"采集完成!")
    print(f"  总节点: {stats['total']}")
    print(f"  住宅 IP: {stats['residential']}")
    print(f"  数据中心: {stats['datacenter']}")
    print(f"  协议分布: {stats['by_protocol']}")
    print(f"  抗干扰: {stats['by_anti_censorship']}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()