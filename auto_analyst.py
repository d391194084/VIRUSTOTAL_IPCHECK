import urllib.request
import urllib.parse  
import json
import sys
import os
from datetime import datetime, timezone, timedelta
from docx import Document
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

def get_vt_data(ip):
    print(f"🔍 [1/4] 正在從 VirusTotal 獲取 {ip} 的數據...")
    vt_key = os.environ.get('VT_API_KEY')
    if not vt_key:
        print("❌ 錯誤：找不到 VT_API_KEY。")
        sys.exit(1)
        
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
        print(f"⚠️ VT 獲取失敗: {e}")
        return "狀態: VT 查詢失敗或無回應"
        
def get_abuse_ch_data(ip):
    print(f"🌍 [1.5/4] 正在深度挖掘 Abuse.ch (ThreatFox + URLhaus) 雙核心開源情資...")
    
    tf_key = os.environ.get('THREATFOX_API_KEY')
    tf_result_text = "⚠️ 未設定 ThreatFox API Key，跳過查詢"
    urlhaus_result_text = "✅ 無命中紀錄 (Clear)"
    
    # --- 1. ThreatFox：萬用字元修復 ---
    if tf_key:
        try:
            url_tf = "https://threatfox-api.abuse.ch/api/v1/"
            
            # 🔥 關鍵修復：用 "IP:*" 觸發模糊比對，覆蓋所有 Port 組合
            payload_tf = {"query": "search_ioc", "search_term": f"{ip}:*"}
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
                    # 🔥 補充：同時擷取完整 IOC（含 Port）方便報告呈現
                    if doc.get('ioc'): ioc_list.append(doc.get('ioc'))
                
                unique_iocs = ', '.join(set(ioc_list)) if ioc_list else '無'
                tf_result_text = (
                    f"🚨 發現惡意紀錄! "
                    f"家族: {', '.join(set(malware))} / "
                    f"標籤: {', '.join(set(tags))} / "
                    f"命中 IOC: {unique_iocs}"  # 讓 AI 能看到是哪些 Port 被標記
                )
            elif res_tf.get('query_status') == 'no_result':
                tf_result_text = "✅ 無命中紀錄 (ThreatFox Clear)"
            else:
                # 保留原始狀態供除錯
                tf_result_text = f"⚠️ 非預期狀態: {res_tf.get('query_status')}"
                
        except urllib.error.HTTPError as e:
            tf_result_text = f"⚠️ HTTP 錯誤 ({e.code}): {e.reason}"
        except Exception as e:
            tf_result_text = f"⚠️ 查詢異常 ({e})"

    # --- 2. 查詢 URLhaus (專注於惡意檔案發佈與主機 IP) ---
    try:
        url_uh = "https://urlhaus-api.abuse.ch/v1/host/"
        data_uh = urllib.parse.urlencode({"host": ip}).encode('utf-8')
        
        req_uh = urllib.request.Request(url_uh, data=data_uh)
        
        # 🔥 關鍵修復 1：加入 User-Agent 偽裝成真人瀏覽器
        req_uh.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36')
        req_uh.add_header('Content-Type', 'application/x-www-form-urlencoded')
        
        # 🔥 關鍵修復 2：遞上 Abuse.ch 萬能金鑰，解鎖 401 限制
        if tf_key:
            req_uh.add_header('Auth-Key', tf_key.strip())
        
        resp_uh = urllib.request.urlopen(req_uh)
        res_uh = json.loads(resp_uh.read())
        
        if res_uh.get('query_status') == 'ok':
            urls_count = len(res_uh.get('urls', []))
            tags = []
            for doc in res_uh.get('urls', []):
                if doc.get('tags'): tags.extend(doc.get('tags'))
            # 過濾掉 None 標籤並去重
            clean_tags = list(set([t for t in tags if t]))
            tag_str = ', '.join(clean_tags) if clean_tags else '無特定標籤'
            
            urlhaus_result_text = f"🚨 發現 {urls_count} 筆惡意關聯! 標籤: {tag_str}"
        else:
            urlhaus_result_text = "✅ 無命中紀錄 (Clear)"
            
    # 這裡就是您剛剛不小心漏掉的 except 區塊 👇
    except urllib.error.HTTPError as e:
        urlhaus_result_text = f"⚠️ 防火牆或授權拒絕 (HTTP {e.code})"
    except Exception as e:
        urlhaus_result_text = f"⚠️ 查詢異常 ({e})"
        
    # 將雙核心結果合併回傳給 AI 進行綜合判斷
    return f"""
    [ThreatFox IOC 庫]: {tf_result_text}
    [URLhaus 惡意主機庫]: {urlhaus_result_text}
    """

# 🔥 修復 NameError：確保參數名稱為 combined_data
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

    tw_tz = timezone(timedelta(hours=8))
    current_time = datetime.now(tw_tz).strftime('%Y-%m-%d %H:%M:%S')

    prompt = f"""
    你是一位頂級資安威脅情資 (CTI) 分析師。請根據以下 VirusTotal 與 Abuse.ch 雙源情資數據，產出繁體中文的專業資安分析報告。
    請綜合評估兩個資料庫的結果。如果 VT 沒報毒但 Abuse.ch 有命中，代表這是新型或特定的惡意基礎設施。
    請不要輸出 Markdown 標記，純文字排版即可，因為我要直接寫入 Word。

    【綜合情資數據】
    {combined_data}

    【輸出格式要求】
    報告標題：客戶安全性分析報告：IP 威脅深度評估
    評估對象：該 IP
    產出時間：{current_time} (台灣標準時間)
    風險等級：(請綜合雙源數據評定 High/Medium/Low)

    一、 綜合威脅情資概述
    二、 VirusTotal 技術偵測與基礎設施分析
    三、 Abuse.ch (ThreatFox) 開源情資交叉比對
    四、 專家分析結論
    五、 建議防護行動
    """
    
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }
    data = json.dumps(payload).encode('utf-8')

    for model_name in available_models:
        print(f"   ⏳ 正在測試模型: {model_name} ...")
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
            print(f"   ⚠️ 拒絕存取: {err_msg} (切換下一個)")
            continue
        except Exception as e:
            print(f"   ⚠️ 發生未知錯誤: {e} (切換下一個)")
            continue

    print("❌ 致命錯誤：清單內所有模型皆被 Google 伺服器拒絕存取。")
    sys.exit(1)

def create_word_document(ip, content):
    print("📝 [3/4] 正在生成 Word (.docx) 報告...")
    doc = Document()
    doc.add_heading(f'資安威脅深度分析報告 - {ip}', 0)
    doc.add_paragraph(content)
    
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
    
    file = service.files().create(
        body=file_metadata, 
        media_body=media, 
        fields='id',
        supportsAllDrives=True
    ).execute()
    
    print(f"✅ 完美登頂！報告已成功存入您的 Google Drive，檔案 ID: {file.get('id')}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python auto_analyst.py <IP地址>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    
    vt_info = get_vt_data(target_ip)
    abuse_info = get_abuse_ch_data(target_ip)
    
    # 這裡將變數定義為 combined_intel，並傳遞給函式
    combined_intel = f"--- VirusTotal 數據 ---\n{vt_info}\n\n--- Abuse.ch 數據 ---\n{abuse_info}"
    
    report_text = analyze_with_gemini(combined_intel)
    doc_name = create_word_document(target_ip, report_text)
    
    print(f"✅ Word 報告已成功在伺服器生成：{doc_name}")
    
    upload_to_drive(doc_name)
