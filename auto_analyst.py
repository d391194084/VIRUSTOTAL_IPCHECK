import urllib.request
import urllib.parse
import json
import sys
import os
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from docx import Document
from docx.shared import Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google.auth.exceptions import RefreshError  # 新增：用於精準捕捉 Token 過期錯誤

# ==========================================
# 核心功能模組：基礎設施驗證與 API 資料獲取
# ==========================================

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        print(f"❌ 錯誤：無效的 IP 格式 '{ip}'，請檢查輸入。")
        return False

def ip_in_fplist(ip: str, fp_list: list) -> bool:
    pattern = r'(?<![0-9\.])' + re.escape(ip) + r'(?![0-9\.])'
    return bool(re.search(pattern, json.dumps(fp_list)))

def get_vt_data(ip):
    vt_key = os.environ.get('VT_API_KEY')
    if not vt_key:
        return "❌ 錯誤：找不到 VT_API_KEY。"
        
    base_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = urllib.request.Request(base_url)
    req.add_header('accept', 'application/json')
    req.add_header('x-apikey', vt_key.strip())
    
    try:
        response = urllib.request.urlopen(req)
        data = json.loads(response.read())['data']['attributes']
        
        stats = data.get('last_analysis_stats', {})
        asn = data.get('asn', 'Unknown')
        as_owner = data.get('as_owner', 'Unknown')
        tags = ", ".join(data.get('tags', []))
        
        return f"""
        狀態: 成功獲取 VT 數據
        目標 IP: {ip}
        地理位置: {data.get('country', 'Unknown')}
        VT 偵測: {stats.get('malicious', 0)} / {sum(stats.values())} (Malicious/Total)
        標籤: {tags}
        ASN 背景: {as_owner} (AS{asn})
        """
    except Exception as e:
        return f"狀態: VT 查詢失敗或無回應 ({e})"

def check_false_positive(ip):
    tf_key = os.environ.get('THREATFOX_API_KEY')
    if not tf_key:
        return "⚠️ 未設定 Abuse.ch 金鑰，跳過白名單檢查"

    url = "https://hunting-api.abuse.ch/api/v1/"
    payload = {"query": "get_fplist", "format": "json"}
    data = json.dumps(payload).encode('utf-8')

    req = urllib.request.Request(url, data=data)
    req.add_header('Content-Type', 'application/json')
    req.add_header('Auth-Key', tf_key.strip())
    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')

    try:
        resp = urllib.request.urlopen(req, timeout=15)
        res = json.loads(resp.read())

        if res.get('query_status') == 'ok':
            fp_list = res.get('data', [])
            if ip_in_fplist(ip, fp_list):
                return f"✅ 【安全確認】此 IP ({ip}) 已被 Abuse.ch 官方明確列為 False Positive (誤報白名單)！請大幅降低其風險評級。"
            else:
                return "不在 Abuse.ch 官方誤報白名單中 (需依賴其他情資判斷)"
        else:
            return f"⚠️ 獲取白名單失敗: {res.get('query_status')}"
    except Exception as e:
        return f"⚠️ 白名單查詢異常 ({e})"

def get_abuse_ch_data(ip):
    tf_key = os.environ.get('THREATFOX_API_KEY')
    tf_result_text = "⚠️ 未設定 ThreatFox API Key，跳過深度獵殺分析"
    urlhaus_result_text = "✅ 查無惡意載體託管紀錄 (Clean)"
    
    if tf_key:
        try:
            url_tf = "https://threatfox-api.abuse.ch/api/v1/"
            payload_tf = {"query": "search_ioc", "search_term": ip}
            data_tf = json.dumps(payload_tf).encode('utf-8')
            
            req_tf = urllib.request.Request(url_tf, data=data_tf)
            req_tf.add_header('Content-Type', 'application/json')
            req_tf.add_header('Auth-Key', tf_key.strip())
            req_tf.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
            
            resp_tf = urllib.request.urlopen(req_tf, timeout=15)
            res_tf = json.loads(resp_tf.read())
            
            if res_tf.get('query_status') == 'ok':
                findings = []
                for doc in res_tf.get('data', []):
                    malware = doc.get('malware_printable', 'Unknown')
                    confidence = doc.get('confidence_level', 0)
                    tags = ", ".join(doc.get('tags') or ["無標籤"])
                    findings.append(f"● [家族: {malware}] (置信度: {confidence}%) - 標籤: {tags}")
                
                tf_result_text = "🚨 【獵殺命中】發現以下惡意威脅關聯：\n      " + "\n      ".join(set(findings))
            elif res_tf.get('query_status') == 'no_result':
                tf_result_text = "✅ 數據庫比對完成：無明確威脅家族命中 (Clear)"
            else:
                tf_result_text = f"⚠️ 查詢狀態異常: {res_tf.get('query_status')}"
        except Exception as e:
            tf_result_text = f"⚠️ ThreatFox 獵殺分析異常 ({e})"

    try:
        url_uh = "https://urlhaus-api.abuse.ch/v1/host/"
        data_uh = urllib.parse.urlencode({"host": ip}).encode('utf-8')
        req_uh = urllib.request.Request(url_uh, data=data_uh)
        req_uh.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
        
        resp_uh = urllib.request.urlopen(req_uh)
        res_uh = json.loads(resp_uh.read())
        
        if res_uh.get('query_status') == 'ok':
            urls_count = len(res_uh.get('urls', []))
            blacklisted = res_uh.get('blacklists', {})
            spamhaus = "🚨 命中" if blacklisted.get('spamhaus_dbl') == 'abused' else "✅ 未命中"
            
            urlhaus_result_text = f"🚨 【惡意託管】此 IP 曾分發 {urls_count} 個惡意檔案！Spamhaus 狀態: {spamhaus}"
        else:
            urlhaus_result_text = "✅ 無惡意 URL 分發紀錄 (Clear)"
            
    except Exception as e:
        urlhaus_result_text = f"⚠️ URLhaus 數據分析異常 ({e})"
        
    return f"\n    [Abuse.ch ThreatFox 深度獵殺]:\n      {tf_result_text}\n    [Abuse.ch URLhaus 行為分析]:\n      {urlhaus_result_text}\n    "
    
def check_firehol_l3(ip: str) -> str:
    """新增：動態下載 FireHOL Level 3 清單並比對 IP"""
    url = "https://iplists.firehol.org/files/firehol_level3.netset"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        resp = urllib.request.urlopen(req, timeout=10)
        data = resp.read().decode('utf-8')
        target = ipaddress.ip_address(ip)
        
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            network = ipaddress.ip_network(line, strict=False)
            if target in network:
                return f"🚨 命中！此 IP 被列入 FireHOL Level 3 黑名單 (匹配網段: {line})"
                
        return "✅ 無命中紀錄 (不在 FireHOL Level 3 中)"
    except Exception as e:
        return f"⚠️ FireHOL 查詢異常 ({e})"

def get_abuseipdb_data(ip: str) -> str:
    """
    獲取 AbuseIPDB 濫用情資 (使用 Free API Key)
    功能：取得該 IP 的濫用信心指數、總回報次數、ISP 資訊與最近回報日期。
    """
    api_key = os.environ.get('ABUSEIPDB_API_KEY')
    if not api_key:
        return "⚠️ 未設定 ABUSEIPDB_API_KEY，跳過 AbuseIPDB 查詢。"

    # API 參數設定
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90',  # 查詢最近 90 天內的回報
        'verbose': 'true'
    }
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key.strip()
    }

    try:
        # 使用標準庫 urllib 進行請求，保持與你原始程式碼一致的風格
        full_url = f"{url}?{urllib.parse.urlencode(querystring)}"
        req = urllib.request.Request(full_url, headers=headers)
        
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = json.loads(response.read())
            data = res_data.get('data', {})
            
            # 提取關鍵欄位
            score = data.get('abuseConfidenceScore', 0)
            total_reports = data.get('totalReports', 0)
            usage_type = data.get('usageType', 'Unknown')
            isp = data.get('isp', 'Unknown')
            domain = data.get('domain', 'Unknown')
            last_reported = data.get('lastReportedAt', 'N/A')

            # 根據分數給予視覺化標記
            if score >= 75:
                status_icon = "🚨 [極高風險]"
            elif score >= 25:
                status_icon = "⚠️ [可疑活動]"
            else:
                status_icon = "✅ [信譽良好]"

            return f"""
        狀態: {status_icon}
        濫用信心指數: {score}%
        最近 90 天回報總數: {total_reports} 次
        最後回報時間: {last_reported}
        ISP/組織: {isp} ({domain})
        使用類型: {usage_type}
            """
    except urllib.error.HTTPError as e:
        if e.code == 429:
            return "⚠️ AbuseIPDB 查詢失敗: 已達到每日 API 配額上限 (Rate Limit)。"
        return f"⚠️ AbuseIPDB 查詢失敗 (HTTP {e.code})"
    except Exception as e:
        return f"⚠️ AbuseIPDB 查詢異常 ({e})"

# ==========================================
# 智慧引擎與排版模組
# ==========================================

def analyze_with_gemini(combined_data):
    print("🧠 [2/4] 正在向 Google 索取可用模型總表並執行全自動闖關...")
    
    api_key = os.environ.get('GEMINI_API_KEY')
    if not api_key:
        print("❌ 錯誤：找不到 GEMINI_API_KEY。")
        sys.exit(1)
        
    api_key = api_key.strip()

    list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        req_list = urllib.request.Request(list_url)
        resp_list = urllib.request.urlopen(req_list)
        models_data = json.loads(resp_list.read())
        
        available_models = [
            m['name'] for m in models_data.get('models', [])
            if 'generateContent' in m.get('supportedGenerationMethods', [])
            and 'gemini' in m.get('name', '').lower()
        ]
        print(f"   📋 系統回報：您的金鑰帳面上共有 {len(available_models)} 個潛在可用模型。")
    except Exception as e:
        print(f"❌ 獲取模型清單失敗: {e}")
        sys.exit(1)

    preferred = [
        "models/gemini-2.5-flash", 
        "models/gemini-2.0-flash", 
        "models/gemini-1.5-flash", 
        "models/gemini-1.5-pro", 
        "models/gemini-pro"
    ]
    
    prioritized_models = [m for m in preferred if m in available_models]
    for m in available_models:
        if m not in prioritized_models:
            prioritized_models.append(m)

    prompt = f"""
    你是一位頂級資安威脅情資 (CTI) 分析師。請根據以下多源情資數據，產出繁體中文的專業資安分析報告。
    請特別注意：
    1. 若在「誤報白名單 (False Positive)」內，請務必大幅降低風險評級，並在結論強調。
    2. 請依據指定的格式輸出，不要包含任何 Markdown 標記 (如 ``` 或 **)，純文字排版即可。

    【綜合情資數據】
    {combined_data}

    【輸出格式要求】
    執行摘要
    風險等級：(High/Medium/Low，請綜合評估各項數據的嚴重性後給出專業判定)

    一、 綜合威脅概述
    二、 VirusTotal 分析與偵測時間軸
    三、 外部威脅情資 (Abuse.ch 與 FireHOL) 交叉比對
    四、 專家結論
    五、 建議防護行動
    """
    
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    data = json.dumps(payload).encode('utf-8')

    for model_name in prioritized_models:
        print(f"   ⏳ 嘗試呼叫最佳模型: {model_name} ...")
        
        url = f"https://generativelanguage.googleapis.com/v1beta/{model_name}:generateContent?key={api_key}"
        
        req = urllib.request.Request(url, data=data)
        req.add_header('Content-Type', 'application/json')
        
        try:
            response = urllib.request.urlopen(req)
            result = json.loads(response.read())
            print(f"   ✅ 闖關成功！最終為您完成分析的模型是：{model_name}")
            return result['candidates'][0]['content']['parts'][0]['text']
            
        except urllib.error.HTTPError as e:
            try:
                error_info = json.loads(e.read().decode())
                err_msg = error_info.get('error', {}).get('message', '未知錯誤')
            except:
                err_msg = str(e)
            print(f"   ⚠️ 失敗 ({e.code}): {err_msg}")
            continue
        except Exception as e:
            print(f"   ⚠️ 發生未知錯誤: {e}")
            continue

    print("❌ 致命錯誤：清單內所有模型皆被 Google 伺服器拒絕存取。請確認您的 API Key 是否有效。")
    sys.exit(1)

def extract_risk_level(content: str) -> str:
    for level in ['High', 'Medium', 'Low']:
        if level.lower() in content.lower():
            return level
    return 'Unknown'

def create_word_document(ip, content):
    print("📝 [3/4] 正在生成企業級 Word (.docx) 報告...")
    doc = Document()
    
    title = doc.add_heading('資安威脅深度分析報告', 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    tw_tz = timezone(timedelta(hours=8))
    table = doc.add_table(rows=3, cols=2)
    table.style = 'Table Grid'
    meta = [
        ('評估對象', ip),
        ('產出時間', datetime.now(tw_tz).strftime('%Y-%m-%d %H:%M:%S') + ' (台灣標準時間)'),
        ('風險等級', extract_risk_level(content)),
    ]
    for i, (label, value) in enumerate(meta):
        table.rows[i].cells[0].text = label
        table.rows[i].cells[1].text = value
        
    doc.add_paragraph()
    
    section_markers = ('執行摘要', '一、', '二、', '三、', '四、', '五、', '六、')
    for line in content.split('\n'):
        stripped = line.strip()
        if not stripped:
            doc.add_paragraph()
            continue
        
        is_heading = False
        for m in section_markers:
            if stripped.startswith(m):
                doc.add_heading(stripped, level=1)
                is_heading = True
                break
                
        if not is_heading:
            doc.add_paragraph(stripped)
            
    filename = f"Security_Report_{ip.replace('.', '_')}.docx"
    doc.save(filename)
    return filename

def upload_to_drive(filename):
    print("☁️ [4/4] 正在使用您本人的專屬授權將報告上傳至 Google Drive...")
    
    client_id = os.environ.get('GDRIVE_CLIENT_ID')
    client_secret = os.environ.get('GDRIVE_CLIENT_SECRET')
    refresh_token = os.environ.get('GDRIVE_REFRESH_TOKEN')
    folder_id = os.environ.get('GDRIVE_FOLDER_ID')
    
    if not all([client_id, client_secret, refresh_token, folder_id]):
        print("❌ 錯誤：缺少 Google Drive OAuth 相關的環境變數！")
        sys.exit(1)

    creds = Credentials(
        token=None,
        refresh_token=refresh_token.strip(),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id.strip(),
        client_secret=client_secret.strip()
    )
    
    service = build('drive', 'v3', credentials=creds)
    
    file_metadata = {'name': filename, 'parents': [folder_id.strip()]}
    media = MediaFileUpload(filename, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
    
    try:
        file = service.files().create(
            body=file_metadata, media_body=media, fields='id', supportsAllDrives=True
        ).execute()
        print(f"✅ 完美登頂！報告已成功存入您的 Google Drive，檔案 ID: {file.get('id')}")
    except RefreshError as e:
        print(f"❌ 錯誤：Google Drive 授權已失效 ({e})。請重新發行 Refresh Token 並更新至環境變數中。")
        sys.exit(1)

# ==========================================
# 主程式執行區塊
# ==========================================

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python auto_analyst.py <IP地址>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    
    if not validate_ip(target_ip):
        sys.exit(1)
    
    # 修改原本的併行執行部分
    print("⚡ 🔍 [1/4] 啟動 5X 引擎：正在並行獲取 VT、Abuse.ch、FireHOL 與 AbuseIPDB 情資...")
    with ThreadPoolExecutor(max_workers=5) as ex:
        f_vt      = ex.submit(get_vt_data, target_ip)
        f_fp      = ex.submit(check_false_positive, target_ip)
        f_abuse   = ex.submit(get_abuse_ch_data, target_ip)
        f_firehol = ex.submit(check_firehol_l3, target_ip)
        f_abuseipdb = ex.submit(get_abuseipdb_data, target_ip) # <--- 新增這行
        
    # 獲取所有結果
    vt_info      = f_vt.result()
    fp_info      = f_fp.result()
    abuse_info   = f_abuse.result()
    firehol_info = f_firehol.result()
    abuseipdb_info = f_abuseipdb.result() # <--- 新增這行
    
    # 將數據餵入 combined_intel 變數
    combined_intel = f"""
    --- VirusTotal 數據 ---
    {vt_info}
    
    --- AbuseIPDB 社群回報數據 ---
    {abuseipdb_info}
    
    --- Abuse.ch 誤報白名單 (False Positive) 檢查 ---
    狀態: {fp_info}
    
    --- Abuse.ch (ThreatFox + URLhaus) 惡意數據 ---
    {abuse_info}

    --- FireHOL Level 3 黑名單比對 ---
    狀態: {firehol_info}
    """
    
    report_text = analyze_with_gemini(combined_intel)
    doc_name = create_word_document(target_ip, report_text)
    upload_to_drive(doc_name)
