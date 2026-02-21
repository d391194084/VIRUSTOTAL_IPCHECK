import urllib.request
import json
import sys
import os
from datetime import datetime

# 1. 改為從環境變數安全讀取 API Key，並加入 .strip() 清除隱形換行符號
def get_api_key():
    key = os.environ.get('VT_API_KEY')
    if not key or not key.strip():
        print("❌ 錯誤：找不到環境變數 VT_API_KEY，請確認 GitHub Secrets 設定。")
        sys.exit(1)
    return key.strip()  # 👈 關鍵修復：把金鑰頭尾的空白與換行符號強制去除

def fetch_vt_data(url, api_key):
    req = urllib.request.Request(url)
    req.add_header('accept', 'application/json')
    req.add_header('x-apikey', api_key)
    try:
        response = urllib.request.urlopen(req)
        return json.loads(response.read())
    except urllib.error.HTTPError as e:
        print(f"⚠️ API 請求錯誤 ({e.code}): {e.reason}")
        return None
    except Exception as e:
        print(f"⚠️ 未知錯誤: {e}")
        return None

def scan_ip(ip):
    api_key = get_api_key()
    base_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    pdns_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=5"
    
    print(f"🔍 正在調用 VirusTotal API 挖掘 IP: {ip} ...\n")
    
    # 獲取基礎資料
    base_data = fetch_vt_data(base_url, api_key)
    if not base_data:
        print("❌ 無法獲取基礎資料，請確認 API Key 是否正確或額度是否耗盡。")
        sys.exit(1)
        
    attrs = base_data['data']['attributes']
    stats = attrs.get('last_analysis_stats', {})
    malicious = stats.get('malicious', 0)
    total = sum(stats.values()) if stats else 0
    asn = attrs.get('asn', 'Unknown')
    as_owner = attrs.get('as_owner', 'Unknown')
    country = attrs.get('country', 'Unknown')
    tags = ", ".join(attrs.get('tags', [])) if attrs.get('tags') else "無特定標籤"
    
    last_date = attrs.get('last_analysis_date')
    formatted_date = datetime.fromtimestamp(last_date).strftime('%Y-%m-%d %H:%M:%S') if last_date else "無近期紀錄"
    
    votes = attrs.get('total_votes', {})
    harmless_votes = votes.get('harmless', 0)
    malicious_votes = votes.get('malicious', 0)
    
    # 獲取關聯網域
    pdns_data = fetch_vt_data(pdns_url, api_key)
    domains = []
    if pdns_data and 'data' in pdns_data:
        for item in pdns_data['data']:
            domain = item.get('attributes', {}).get('host_name', '')
            date_ts = item.get('attributes', {}).get('date')
            if domain:
                res_date = datetime.fromtimestamp(date_ts).strftime('%Y-%m-%d') if date_ts else "未知"
                domains.append(f"  - {domain} (解析時間: {res_date})")
    domain_str = "\n".join(domains) if domains else "  - 近期無關聯網域解析紀錄"

    # 2. 準備輸出格式
    output_text = f"""========================================
✨ 請將以下內容「完整複製」並貼給 Gem ✨
========================================
目標 IP: {ip}
地理位置: {country}
最後掃描: {formatted_date}
引擎偵測: {malicious} / {total} (Malicious/Total)
社群評價: {malicious_votes} 票惡意 / {harmless_votes} 票無害
威脅標籤: {tags}
ASN 背景: {as_owner} (AS{asn})
關聯網域 (Passive DNS): 
{domain_str}
========================================"""

    print(output_text)

    # 3. 將結果寫入實體報告檔案 (供 GitHub Actions 讀取顯示)
    with open("report.md", "w", encoding="utf-8") as f:
        f.write(output_text)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python vt_scan.py <IP地址>")
        sys.exit(1)
    scan_ip(sys.argv[1])
