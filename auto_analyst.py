import urllib.request
import json
import sys
import os
from datetime import datetime
from docx import Document
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from datetime import datetime, timezone, timedelta

def get_vt_data(ip):
    print(f"🔍 [1/4] 正在從 VirusTotal 獲取 {ip} 的數據...")
    vt_key = os.environ.get('VT_API_KEY')
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
        目標 IP: {ip}
        地理位置: {data.get('country', 'Unknown')}
        VT 偵測: {stats.get('malicious', 0)} / {sum(stats.values())} (Malicious/Total)
        標籤: {tags}
        ASN 背景: {as_owner} (AS{asn})
        """
    except Exception as e:
        print(f"❌ VT 獲取失敗: {e}")
        sys.exit(1)
        
def get_abuse_ch_data(ip):
    print(f"🌍 [1.5/4] 正在查詢 Abuse.ch (ThreatFox) 開源情資資料庫...")
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "search_ioc", "search_term": ip}
    data = json.dumps(payload).encode('utf-8')
    
    req = urllib.request.Request(url, data=data)
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    
    try:
        response = urllib.request.urlopen(req)
        result = json.loads(response.read())
        
        if result.get('query_status') == 'ok':
            # 如果有命中，提取惡意軟體名稱與標籤
            tags = []
            malware = []
            for doc in result.get('data', []):
                if doc.get('tags'): tags.extend(doc.get('tags'))
                if doc.get('malware_printable'): malware.append(doc.get('malware_printable'))
            
            # 去除重複項
            tags = list(set(tags))
            malware = list(set(malware))
            
            return f"""
            狀態: 🚨 發現惡意紀錄 (Hit)
            關聯惡意軟體家族: {', '.join(malware)}
            威脅標籤: {', '.join(tags)}
            """
        else:
            return "狀態: ✅ 無命中紀錄 (Clear)"
    except Exception as e:
        print(f"⚠️ Abuse.ch 查詢發生異常: {e}")
        return "狀態: 查詢失敗或無回應"

def analyze_with_gemini(vt_data):
    print("🧠 [2/4] 正在向 Google 索取您專屬的「可用模型總表」並執行全自動闖關...")
    
    api_key = os.environ.get('GEMINI_API_KEY')
    if not api_key:
        print("❌ 錯誤：找不到 GEMINI_API_KEY。")
        sys.exit(1)
        
    api_key = api_key.strip()
    
    # --- 步驟 1：取得這把金鑰能看到的所有模型 ---
    list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        req_list = urllib.request.Request(list_url)
        resp_list = urllib.request.urlopen(req_list)
        models_data = json.loads(resp_list.read())
        
        # 抓出所有支援文字生成 (generateContent) 且是 gemini 的模型
        available_models = [
            m['name'] for m in models_data.get('models', [])
            if 'generateContent' in m.get('supportedGenerationMethods', [])
            and 'gemini' in m.get('name', '').lower()
        ]
        
        print(f"   📋 系統回報：您的金鑰帳面上共有 {len(available_models)} 個潛在可用模型。")
    except Exception as e:
        print(f"❌ 獲取模型清單失敗: {e}")
        sys.exit(1)

    # 取得目前台灣時間 (UTC+8)
    tw_tz = timezone(timedelta(hours=8))
    current_time = datetime.now(tw_tz).strftime('%Y-%m-%d %H:%M:%S')
    
    # --- 步驟 2：準備分析資料 ---
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

    # --- 步驟 3：全目錄暴力闖關測試 ---
    # 程式會一個一個試，直到遇到 HTTP 200 (成功) 為止
    for model_name in available_models:
        print(f"   ⏳ 正在測試模型: {model_name} ...")
        # model_name 已經包含 "models/" 前綴，例如 "models/gemini-1.5-pro-001"
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
            
            # 遇到 404 或「不再開放給新用戶」，印出警告並繼續下一個
            print(f"   ⚠️ 拒絕存取: {err_msg} (切換下一個)")
            continue
        except Exception as e:
            print(f"   ⚠️ 發生未知錯誤: {e} (切換下一個)")
            continue

    # 如果把十幾個模型全試完了都不行，代表這把金鑰被 Google 徹底限制了
    print("❌ 致命錯誤：清單內所有模型皆被 Google 伺服器拒絕存取。")
    print("💡 建議解法：Google 可能鎖定了您當前的 Cloud 專案。請使用另一個全新的 Google 帳號，重新申請一組 API Key。")
    sys.exit(1)
    
def create_word_document(ip, content):
    print("📝 [3/4] 正在生成 Word (.docx) 報告...")
    doc = Document()
    doc.add_heading(f'資安威脅分析報告 - {ip}', 0)
    doc.add_paragraph(content)
    
    filename = f"Security_Report_{ip.replace('.', '_')}.docx"
    doc.save(filename)
    return filename
    
def upload_to_drive(filename):
    print("☁️ [4/4] 正在使用您本人的專屬授權將報告上傳至 Google Drive...")
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload
    
    # 讀取 GitHub Secrets
    client_id = os.environ.get('GDRIVE_CLIENT_ID').strip()
    client_secret = os.environ.get('GDRIVE_CLIENT_SECRET').strip()
    refresh_token = os.environ.get('GDRIVE_REFRESH_TOKEN').strip()
    folder_id = os.environ.get('GDRIVE_FOLDER_ID').strip()
    
    # 使用 Refresh Token 自動換取登入權限
    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id,
        client_secret=client_secret
    )
    
    service = build('drive', 'v3', credentials=creds)
    
    file_metadata = {'name': filename, 'parents': [folder_id]}
    media = MediaFileUpload(filename, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
    
    # 執行上傳 (supportsAllDrives=True 確保相容性)
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
    
    # 執行工作流
    vt_info = get_vt_data(target_ip)
    abuse_info = get_abuse_ch_data(target_ip)
    
    # 組合兩份情資
    combined_intel = f"--- VirusTotal 數據 ---\n{vt_info}\n\n--- Abuse.ch 數據 ---\n{abuse_info}"
    
    # 將組合後的情資送給 Gemini 分析
    report_text = analyze_with_gemini(combined_intel)
    doc_name = create_word_document(target_ip, report_text)
    
    print(f"✅ Word 報告已成功在伺服器生成：{doc_name}")
    # ...(保留您後續上傳 Google Drive 的程式碼)
