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
    tf_result_text = "⚠️ 未設定 ThreatFox API Key，跳過查詢"
    urlhaus_result_text = "✅ 無命中紀錄 (Clear)"
    
    if tf_key:
        try:
            url_tf = "https://threatfox-api.abuse.ch/api/v1/"
            payload_tf = {"query": "search_ioc", "search_term": ip}
            data_tf = json.dumps(payload_tf).encode('utf-8')
            
            req_tf = urllib.request.Request(url_tf, data=data_tf)
            req_tf.add_header('Content-Type', 'application/json')
            req_tf.add_header('Accept', 'application/json')
            req_tf.add_header('Auth-Key', tf_key.strip())
            req_tf.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
            
            resp_tf = urllib.request.urlopen(req_tf, timeout=15)
            res_tf = json.loads(resp_tf.read())
            
            if res_tf.get('query_status') == 'ok':
                tags, malware, ioc_list = [], [], []
                for doc in res_tf.get('data', []):
                    if doc.get('tags'): tags.extend(doc.get('tags'))
                    if doc.get('malware_printable'): malware.append(doc.get('malware_printable'))
                    if doc.get('ioc'): ioc_list.append(doc.get('ioc'))
                
                unique_iocs = ', '.join(set(ioc_list)) if ioc_list else '無'
                tf_result_text = f"🚨 發現惡意紀錄! 家族: {', '.join(set(malware))} / 標籤: {', '.join(set(tags))} / 命中 IOC: {unique_iocs}"
            elif res_tf.get('query_status') == 'no_result':
                tf_result_text = "✅ 無命中紀錄 (ThreatFox 查無精確匹配)"
            else:
                tf_result_text = f"⚠️ 狀態不明: {res_tf.get('query_status')}"
        except Exception as e:
            tf_result_text = f"⚠️ 查詢異常 ({e})"

    try:
        url_uh = "https://urlhaus-api.abuse.ch/v1/host/"
        data_uh = urllib.parse.urlencode({"host": ip}).encode('utf-8')
        
        req_uh = urllib.request.Request(url_uh, data=data_uh)
        req_uh.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36')
        req_uh.add_header('Content-Type', 'application/x-www-form-urlencoded')
        if tf_key: req_uh.add_header('Auth-Key', tf_key.strip())
        
        resp_uh = urllib.request.urlopen(req_uh)
        res_uh = json.loads(resp_uh.read())
        
        if res_uh.get('query_status') == 'ok':
            urls_count = len(res_uh.get('urls', []))
            tags = []
            for doc in res_uh.get('urls', []):
                if doc.get('tags'): tags.extend(doc.get('tags'))
            
            clean_tags = list(set([t for t in tags if t]))
            tag_str = ', '.join(clean_tags) if clean_tags else '無特定標籤'
            urlhaus_result_text = f"🚨 發現 {urls_count} 筆惡意關聯! 標籤: {tag_str}"
        else:
            urlhaus_result_text = "✅ 無命中紀錄 (Clear)"
            
    except Exception as e:
        urlhaus_result_text = f"⚠️ 查詢異常 ({e})"
        
    return f"\n    [ThreatFox IOC 庫]: {tf_result_text}\n    [URLhaus 惡意主機庫]: {urlhaus_result_text}\n    "

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

    # 1. 動態獲取清單
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

    # 2. 優先排序 (把強的放前面，沒中的就維持原清單)
    preferred = ["models/gemini-2.5-flash", "models/gemini-2.0-flash", "models/gemini-1.5-flash", "models/gemini-pro"]
    prioritized_models = [m for m in preferred if m in available_models] + [m for m in available_models if m not in preferred]

    tw_tz = timezone(timedelta(hours=8))
    current_time = datetime.now(tw_tz).strftime('%Y-%m-%d %H:%M:%S')

    prompt = f"""
    你是一位頂級資安威脅情資 (CTI) 分析師。請根據以下多源情資數據，產出繁體中文的專業資安分析報告。
    請特別注意：
    1. 若在「誤報白名單 (False Positive)」內，請務必大幅降低風險評級，並在結論強調。
    2. 請依據指定的格式輸出，不要包含任何 Markdown 標記 (如 ``` 或 **)，純文字排版即可。

    【綜合情資數據】
    {combined_data}

    【輸出格式要求】
    執行摘要
    風險評分矩陣：(請基於數據產出文字表格，包含 VT 偵測率 30%、ThreatFox 30%、URLhaus 20%、白名單 10%、ASN 10% 等權重評分)
    風險等級：(High/Medium/Low)

    一、 綜合威脅概述
    二、 VirusTotal 分析與偵測時間軸
    三、 Abuse.ch (白名單、ThreatFox 與 URLhaus) 交叉比對
    四、 專家結論
    五、 建議防護行動
    """
    
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    data = json.dumps(payload).encode('utf-8')

    # 3. 依序闖關 (成功就會立刻 return，不會暴衝)
    for model_name in prioritized_models:
        print(f"   ⏳ 嘗試呼叫最佳模型: {model_name} ...")
        
        # ⚠️ 這裡絕對乾淨，沒有任何 Markdown 連結格式
        url = f"[https://generativelanguage.googleapis.com/v1beta/](https://generativelanguage.googleapis.com/v1beta/){model_name}:generateContent?key={api_key}"
        
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
        # ⚠️ 這裡也已經清洗乾淨
        token_uri="[https://oauth2.googleapis.com/token](https://oauth2.googleapis.com/token)",
        client_id=client_id.strip(),
        client_secret=client_secret.strip()
    )
    
    service = build('drive', 'v3', credentials=creds)
    
    file_metadata = {'name': filename, 'parents': [folder_id.strip()]}
    media = MediaFileUpload(filename, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
    
    file = service.files().create(
        body=file_metadata, media_body=media, fields='id', supportsAllDrives=True
    ).execute()
    print(f"✅ 完美登頂！報告已成功存入您的 Google Drive，檔案 ID: {file.get('id')}")

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
    
    print("⚡ 🔍 [1/4] 啟動 3X 引擎：正在並行獲取 VT 與 Abuse.ch 雙核心情資...")
    with ThreadPoolExecutor(max_workers=3) as ex:
        f_vt    = ex.submit(get_vt_data, target_ip)
        f_fp    = ex.submit(check_false_positive, target_ip)
        f_abuse = ex.submit(get_abuse_ch_data, target_ip)
        
    vt_info, fp_info, abuse_info = f_vt.result(), f_fp.result(), f_abuse.result()
    
    combined_intel = f"""
    --- VirusTotal 數據 ---
    {vt_info}
    
    --- Abuse.ch 誤報白名單 (False Positive) 檢查 ---
    狀態: {fp_info}
    
    --- Abuse.ch (ThreatFox + URLhaus) 惡意數據 ---
    {abuse_info}
    """
    
    report_text = analyze_with_gemini(combined_intel)
    doc_name = create_word_document(target_ip, report_text)
    upload_to_drive(doc_name)
