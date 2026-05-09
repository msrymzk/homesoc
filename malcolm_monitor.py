import argparse
import json
import logging
import os
import socket
import sys
from datetime import datetime, timezone, timedelta

import requests
import urllib3
from dotenv import load_dotenv

# 警告を無効化 (自己署名証明書用)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ログ設定
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# .envファイルの読み込み
load_dotenv()

OPENSEARCH_URL = os.environ.get("MALCOLM_OPENSEARCH_URL", "")
USERNAME = os.environ.get("MALCOLM_USER", "")
PASSWORD = os.environ.get("MALCOLM_PASS", "")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")

STATE_FILE = "known_devices.json"
IP_HOST_FILE = "ip_to_host.json"

ip_mapping_cache = {}

class MalcolmClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        
    def query(self, index, payload):
        url = f"{self.base_url}/{index}/_search"
        headers = {"Content-Type": "application/json"}
        
        try:
            logger.debug(f"API Request to {url} with payload: {json.dumps(payload, ensure_ascii=False)}")
            response = requests.post(
                url, 
                auth=self.auth, 
                headers=headers, 
                json=payload, 
                verify=False, 
                timeout=30
            )
            response.raise_for_status()
            resp_json = response.json()
            logger.debug(f"API Response: {json.dumps(resp_json, ensure_ascii=False)}")
            return resp_json
        except requests.exceptions.RequestException as e:
            logger.error(f"OpenSearch API error: {e}")
            if response is not None:
                logger.error(f"Response: {response.text}")
            return None

def send_webhook(message, blocks=None):
    if not WEBHOOK_URL:
        logger.warning("Webhook URL is not set. Skipping notification.")
        logger.info(f"Notification Content: {message}")
        return

    is_discord = "discord.com" in WEBHOOK_URL

    if is_discord:
        # Discordの文字数制限(2000文字)対策として、改行位置で分割して送信する
        chunks = []
        current_chunk = ""
        for line in message.split('\n'):
            if len(line) > 1900:
                if current_chunk:
                    chunks.append(current_chunk)
                    current_chunk = ""
                for j in range(0, len(line), 1900):
                    chunks.append(line[j:j+1900])
                continue
                
            if len(current_chunk) + len(line) + 1 > 1900:
                chunks.append(current_chunk)
                current_chunk = line + "\n"
            else:
                current_chunk += line + "\n"
        if current_chunk:
            chunks.append(current_chunk)
            
        for i, chunk in enumerate(chunks):
            payload = {"content": chunk}
            try:
                response = requests.post(WEBHOOK_URL, json=payload, timeout=10)
                response.raise_for_status()
                if i == len(chunks) - 1:
                    logger.info("Discord webhook sent successfully.")
            except requests.exceptions.RequestException as e:
                logger.error(f"Discord Webhook error: {e}")
                if e.response is not None:
                    logger.error(f"Response: {e.response.text}")
    else:
        # Slack / General
        payload = {"text": message}
        if blocks:
            payload["blocks"] = blocks
    
        try:
            response = requests.post(WEBHOOK_URL, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("Webhook sent successfully.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Webhook error: {e}")
            if e.response is not None:
                logger.error(f"Response: {e.response.text}")

def update_dhcp_mapping(client):
    global ip_mapping_cache
    logger.info("Updating IP-to-Hostname mapping (MAC-based)...")
    
    # Step 0: IP to Hostname from DNS logs (mDNS *.local etc.)
    dns_payload = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"term": {"event.dataset": "dns"}},
                    {"exists": {"field": "zeek.dns.answers"}},
                    {"wildcard": {"zeek.dns.query": "*.local"}}
                ]
            }
        },
        "aggs": {
            "dns_mapping": {
                "terms": {"field": "zeek.dns.answers", "size": 1000},
                "aggs": {
                    "latest_dns": {
                        "top_hits": {
                            "sort": [{"@timestamp": {"order": "desc"}}],
                            "_source": {"includes": ["zeek.dns.query"]},
                            "size": 1
                        }
                    }
                }
            }
        }
    }
    
    # Step 1: MAC to Hostname from DHCP logs
    dhcp_payload = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"exists": {"field": "zeek.dhcp.host_name"}},
                    {"exists": {"field": "zeek.dhcp.mac"}}
                ]
            }
        },
        "aggs": {
            "mac_mapping": {
                "terms": {"field": "zeek.dhcp.mac", "size": 1000},
                "aggs": {
                    "latest_dhcp": {
                        "top_hits": {
                            "sort": [{"@timestamp": {"order": "desc"}}],
                            "_source": {"includes": ["zeek.dhcp.host_name"]},
                            "size": 1
                        }
                    }
                }
            }
        }
    }
    
    # Step 2: IP to MAC from all traffic logs
    ip_payload = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"exists": {"field": "source.ip"}},
                    {"exists": {"field": "source.mac"}}
                ]
            }
        },
        "aggs": {
            "ip_mapping": {
                "terms": {"field": "source.ip", "size": 5000},
                "aggs": {
                    "latest_mac": {
                        "top_hits": {
                            "sort": [{"@timestamp": {"order": "desc"}}],
                            "_source": {"includes": ["source.mac"]},
                            "size": 1
                        }
                    }
                }
            }
        }
    }
    
    dns_data = client.query("malcolm_*", dns_payload)
    dhcp_data = client.query("malcolm_*", dhcp_payload)
    ip_data = client.query("malcolm_*,arkime_sessions3-*", ip_payload)
    
    dns_to_host = {}
    if dns_data and "aggregations" in dns_data:
        buckets = dns_data["aggregations"]["dns_mapping"]["buckets"]
        for b in buckets:
            ip = b["key"]
            hits = b.get("latest_dns", {}).get("hits", {}).get("hits", [])
            if hits:
                query_name = hits[0]["_source"].get("zeek", {}).get("dns", {}).get("query")
                if query_name and query_name.endswith(".local"):
                    host_name = query_name[:-6] # remove .local
                    
                    # _matterd._udp などのサービス名単体の場合は無視する
                    if host_name.startswith("_"):
                        continue
                        
                    # Apple-TV._airplay._tcp などの場合は先頭のデバイス名だけを抽出する
                    if "._" in host_name:
                        host_name = host_name.split("._")[0]
                        
                    dns_to_host[ip] = host_name
                    
    mac_to_host = {}
    if dhcp_data and "aggregations" in dhcp_data:
        buckets = dhcp_data["aggregations"]["mac_mapping"]["buckets"]
        for b in buckets:
            mac = b["key"]
            hits = b.get("latest_dhcp", {}).get("hits", {}).get("hits", [])
            if hits:
                host_name = hits[0]["_source"].get("zeek", {}).get("dhcp", {}).get("host_name")
                if host_name:
                    mac_to_host[mac] = host_name
                    
    new_mapping = {}
    if ip_data and "aggregations" in ip_data:
        buckets = ip_data["aggregations"]["ip_mapping"]["buckets"]
        for b in buckets:
            ip = b["key"]
            
            hits = b.get("latest_mac", {}).get("hits", {}).get("hits", [])
            if hits:
                mac_list = hits[0]["_source"].get("source", {}).get("mac", [])
                if mac_list:
                    mac = mac_list[0]
                    
                    # Priority 1: DHCP
                    if mac in mac_to_host:
                        new_mapping[ip] = mac_to_host[mac]
                        continue
                        
                    # Priority 2: DNS / mDNS
                    if ip in dns_to_host:
                        new_mapping[ip] = dns_to_host[ip]
                        continue
                        
                    # Priority 3: MAC
                    new_mapping[ip] = mac
                    
    if os.path.exists(IP_HOST_FILE):
        try:
            with open(IP_HOST_FILE, "r") as f:
                ip_mapping_cache = json.load(f)
        except json.JSONDecodeError:
            pass
            
    ip_mapping_cache.update(new_mapping)
    
    with open(IP_HOST_FILE, "w") as f:
        json.dump(ip_mapping_cache, f, indent=2)
        
    logger.info(f"IP-to-Hostname mapping updated. Total entries: {len(ip_mapping_cache)}")

def resolve_ip(ip):
    global ip_mapping_cache
    if not ip_mapping_cache:
        if os.path.exists(IP_HOST_FILE):
            try:
                with open(IP_HOST_FILE, "r") as f:
                    ip_mapping_cache = json.load(f)
            except json.JSONDecodeError:
                pass
    
    host_name = ip_mapping_cache.get(ip)
    if host_name:
        if host_name == ip:
            return ip
        return f"{host_name} ({ip})"
        
    try:
        # 短いタイムアウトを設定して逆引きによる遅延を防ぐ
        socket.setdefaulttimeout(1.0)
        host_name, _, _ = socket.gethostbyaddr(ip)
        ip_mapping_cache[ip] = host_name
        with open(IP_HOST_FILE, "w") as f:
            json.dump(ip_mapping_cache, f, indent=2)
        return f"{host_name} ({ip})"
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        # 逆引き失敗時はIPそのものをキャッシュして再試行を防ぐ
        ip_mapping_cache[ip] = ip
        with open(IP_HOST_FILE, "w") as f:
            json.dump(ip_mapping_cache, f, indent=2)
            
    return ip

def feature_a_threat_detection(client):
    logger.info("Running Feature A: Threat Detection (Last 15m)")
    # Suricataアラートの中で、Severity 1 (High) または 2 (Medium) のものを取得
    payload = {
        "size": 1000,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-15m"}}},
                    {"term": {"event.kind": "alert"}},
                    {"terms": {"suricata.eve.alert.severity": [1]}}
                ]
            }
        }
    }
    
    data = client.query("malcolm_beats_suricata-*", payload)
    if not data or "hits" not in data:
        return
    
    hits = data["hits"]["hits"]
    if not hits:
        logger.info("No high severity alerts found.")
        return
        
    # 集約処理
    alerts_summary = {}
    for hit in hits:
        source = hit["_source"]
        src_ip = source.get("source", {}).get("ip", "Unknown")
        dest_ip = source.get("destination", {}).get("ip", "Unknown")
        rule_name = source.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature", "Unknown Rule")
        
        key = f"{resolve_ip(src_ip)} -> {resolve_ip(dest_ip)} : {rule_name}"
        alerts_summary[key] = alerts_summary.get(key, 0) + 1
        
    # 通知の組み立て
    text_lines = ["*【重大アラート検知】*"]
    for key, count in alerts_summary.items():
        text_lines.append(f"- `{key}` : {count}件")
        
    send_webhook("\n".join(text_lines))

def load_known_devices():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    return []

def save_known_devices(devices):
    with open(STATE_FILE, "w") as f:
        json.dump(devices, f, indent=2)

def feature_b_unknown_devices(client):
    logger.info("Running Feature B: Unknown Device Detection (Last 1h)")
    # 過去1時間のアクティブなIPアドレスを取得
    payload = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-1h"}}}
                ],
                "filter": [
                    {"terms": {"network.direction": ["internal", "outbound"]}}
                ]
            }
        },
        "aggs": {
            "active_ips": {
                "terms": {"field": "source.ip", "size": 1000}
            }
        }
    }
    
    data = client.query("malcolm_*,arkime_sessions3-*", payload)
    if not data or "aggregations" not in data:
        return
        
    buckets = data["aggregations"]["active_ips"]["buckets"]
    current_ips = [b["key"] for b in buckets]
    
    known_devices = load_known_devices()
    new_devices = []
    
    for ip in current_ips:
        if ip not in known_devices:
            new_devices.append(ip)
            known_devices.append(ip)
            
    if new_devices:
        logger.info(f"Found new devices: {new_devices}")
        save_known_devices(known_devices)
        text = "*【新規デバイス検知】*\nネットワーク上で未知のIPアドレスを検知しました:\n"
        for ip in new_devices:
            text += f"- `{resolve_ip(ip)}`\n"
        send_webhook(text)
    else:
        logger.info("No new devices found.")

def feature_c_daily_summary(client):
    logger.info("Running Feature C: Daily Summary Report (Last 24h)")
    
    payload = {
        "size": 0,
        "query": {
            "range": {"@timestamp": {"gte": "now-24h"}}
        },
        "aggs": {
            "total_bytes": {"sum": {"field": "network.bytes"}},
            "active_devices": {
                "filter": {
                    "terms": {"network.direction": ["internal", "outbound"]}
                },
                "aggs": {
                    "count": {"cardinality": {"field": "source.ip"}}
                }
            },
            "top_countries": {"terms": {"field": "destination.geo.country_iso_code", "size": 10}},
            "top_protocols": {"terms": {"field": "protocol", "size": 10}},
            "http_4xx": {"filter": {"range": {"http.response.status_code": {"gte": 400, "lt": 500}}}},
            "http_5xx": {"filter": {"range": {"http.response.status_code": {"gte": 500, "lt": 600}}}},
            "top_talkers": {
                "terms": {"field": "source.ip", "size": 50, "order": {"total_bytes": "desc"}},
                "aggs": {
                    "total_bytes": {"sum": {"field": "network.bytes"}},
                    "directions": {"terms": {"field": "network.direction", "size": 3}}
                }
            }
        }
    }
    
    # NXDOMAINの取得
    nx_payload = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"term": {"dns.response_code": "NXDOMAIN"}}
                ]
            }
        }
    }
    
    # 脅威アラートの取得 (過去24時間のSeverity 1, 2)
    alert_payload = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"term": {"event.kind": "alert"}},
                    {"terms": {"suricata.eve.alert.severity": [1, 2]}}
                ]
            }
        },
        "aggs": {
            "top_alerts": {
                "terms": {"field": "suricata.eve.alert.signature", "size": 10}
            }
        }
    }
    
    data = client.query("malcolm_*,arkime_sessions3-*", payload)
    nx_data = client.query("malcolm_dns-*", nx_payload)
    alert_data = client.query("malcolm_beats_suricata-*", alert_payload)
    
    if not data or not nx_data:
        logger.error("Failed to fetch data for daily summary.")
        return
        
    aggs = data.get("aggregations", {})
    
    total_bytes = aggs.get("total_bytes", {}).get("value", 0)
    active_devices = aggs.get("active_devices", {}).get("count", {}).get("value", 0)
    http_4xx = aggs.get("http_4xx", {}).get("doc_count", 0)
    http_5xx = aggs.get("http_5xx", {}).get("doc_count", 0)
    nx_count = nx_data.get("hits", {}).get("total", {}).get("value", 0)
    alert_count = alert_data.get("hits", {}).get("total", {}).get("value", 0) if alert_data else 0
    
    top_countries = aggs.get("top_countries", {}).get("buckets", [])
    top_protocols = aggs.get("top_protocols", {}).get("buckets", [])
    top_talkers = aggs.get("top_talkers", {}).get("buckets", [])
    top_alerts = alert_data.get("aggregations", {}).get("top_alerts", {}).get("buckets", []) if alert_data else []
    
    mb_total = total_bytes / (1024 * 1024)
    gb_total = mb_total / 1024
    total_str = f"{gb_total:.2f} GB" if gb_total > 1 else f"{mb_total:.2f} MB"
    
    end_time = datetime.now()
    start_time = end_time - timedelta(days=1)
    period_str = f"{start_time.strftime('%Y-%m-%d %H:%M')} 〜 {end_time.strftime('%Y-%m-%d %H:%M')}"
    
    text_lines = ["*【日次ネットワークレポート】*"]
    text_lines.append(f"• *集計期間*: {period_str}")
    text_lines.append(f"• *1日の総通信量*: {total_str}")
    text_lines.append(f"• *アクティブデバイス数*: {active_devices} 台")
    text_lines.append(f"• *HTTP エラー数*: 4xx ({http_4xx}件) / 5xx ({http_5xx}件)")
    text_lines.append(f"• *DNS NXDOMAIN エラー*: {nx_count} 件")
    text_lines.append(f"• *脅威アラート (High/Medium)*: {alert_count} 件")
    
    if alert_count > 0:
        text_lines.append("\n*🚨 脅威アラート 内訳 (Top 10)*:")
        for b in top_alerts:
            text_lines.append(f"  - `{b['key']}` : {b['doc_count']} 件")
    
    text_lines.append("\n*🌍 アクセス先 国別ランキング (Top 10)*:")
    if top_countries:
        for b in top_countries:
            text_lines.append(f"  - `{b['key']}` : {b['doc_count']} セッション")
    else:
        text_lines.append("  - データなし")

    text_lines.append("\n*🔌 プロトコル割合 (Top 10)*:")
    if top_protocols:
        for b in top_protocols:
            text_lines.append(f"  - `{b['key']}` : {b['doc_count']} セッション")
    else:
        text_lines.append("  - データなし")

    text_lines.append("\n*💻 トップトラフィック端末 (Top 50)*:")
    if top_talkers:
        for b in top_talkers:
            ip = b["key"]
            bytes_t = b["total_bytes"]["value"]
            mb_t = bytes_t / (1024 * 1024)
            gb_t = mb_t / 1024
            
            dirs = [d["key"] for d in b.get("directions", {}).get("buckets", [])]
            dir_str = f" [{', '.join(dirs)}]" if dirs else ""
            
            if gb_t > 1:
                text_lines.append(f"  - `{resolve_ip(ip)}`{dir_str} : {gb_t:.2f} GB")
            else:
                text_lines.append(f"  - `{resolve_ip(ip)}`{dir_str} : {mb_t:.2f} MB")
    else:
        text_lines.append("  - データなし")
        
    send_webhook("\n".join(text_lines))

def main():
    parser = argparse.ArgumentParser(description="Malcolm Network Monitor")
    parser.add_argument("--mode", required=True, choices=["alerts", "new_devices", "daily_summary"],
                        help="Execution mode")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging (shows API payloads and responses)")
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
        
    client = MalcolmClient(OPENSEARCH_URL, USERNAME, PASSWORD)
    
    update_dhcp_mapping(client)
    
    if args.mode == "alerts":
        feature_a_threat_detection(client)
    elif args.mode == "new_devices":
        feature_b_unknown_devices(client)
    elif args.mode == "daily_summary":
        feature_c_daily_summary(client)

if __name__ == "__main__":
    main()
