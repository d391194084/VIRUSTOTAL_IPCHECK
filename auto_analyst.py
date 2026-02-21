import urllib.request
import json
import sys
import os
from datetime import datetime
from docx import Document
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

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

def analyze_with_gemini(vt_data):
    print("🧠 [2/4] 正在詢問 Google 伺服器可用的 AI 模型清單 (ListModels)...")
    
    api_key = os.environ.get('GEMINI_API_KEY')
    if not api_key:
        print("❌ 錯誤：找不到 GEMINI_API_KEY。")
        sys.exit(1)
        
    api_key = api_key.strip()
    
    # --- 步驟 1：逼問伺服器，拿取這把金鑰的「專屬菜單」 ---
    list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        req_list = urllib.request.Request(list_url)
        resp_list = urllib.request.urlopen(req_list)
        models_data = json.loads(resp_list.read())
        
        # 篩選出支援文字生成 (generateContent) 的 Gemini 模型
        available_models = [
            m['name'] for m in models_data.get('models', [])
            if 'generateContent' in m.get('supportedGenerationMethods', []) and 'gemini' in m.get('name', '').lower()
        ]
        
        if not available_models:
            print("❌ 致命錯誤：您的 API Key 沒有權限存取任何 Gemini 模型！請檢查 Google AI Studio 帳號狀態。")
            sys.exit(1)
            
        # 自動從菜單中挑選最佳模型 (優先找 1.5-flash 或 2.0-flash)
        chosen_model = None
        for pref in ['gemini-1.5-flash', 'gemini-2.0-flash', 'gemini-1.5-pro', 'gemini-pro']:
            matched = [m for m in available_models if pref in m]
            if matched:
                chosen_model = matched[0] # 選擇比對成功的第一個 (例如 models/gemini-1.5-flash-001)
                break
                
        if not chosen_model:
            chosen_model = available_models[0] # 如果都沒對上，就硬抓清單裡的第一個可用模型
            
        print(f"   ✅ 成功獲取授權清單！系統自動選定您的專屬可用模型：{chosen_model}")

    except Exception as e:
        print(f"❌ 獲取模型清單失敗: {e}")
        sys.exit(1)

    # --- 步驟 2：使用剛才抓到的正確名字，正式發送分析請求 ---
    print(f"🧠 正在將數據傳送給 {chosen_model} 進行深度分析...")
    
    # 注意這裡的 URL 是動態注入的，絕對不會再 404！
    url = f"https://generativelanguage.googleapis.com/v1beta/{chosen_model}:generateContent?key={api_key}"
    
    prompt = f"""
    你是一位頂級資安分析師。請根據以下 VirusTotal API 數據，產出繁體中文的專業資安分析報告。
    請不要輸出 Markdown 標記，純文字排版即可，因為我要直接寫入 Word。

    【數據】
    {vt_data}

    【輸出格式要求】
    報告標題：客戶安全性分析報告：IP 威脅評估
    評估對象：該 IP
    風險等級：(請根據數據評定 High/Medium/Low)

    一、 威脅情資概述
    二、 技術偵測與基礎設施背景分析
    三、 專家分析結論
    四、 建議防護行動
    """
    
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }
    data = json.dumps(payload).encode('utf-8')
    
    req = urllib.request.Request(url, data=data)
    req.add_header('Content-Type', 'application/json')
    
    try:
        response = urllib.request.urlopen(req)
        result = json.loads(response.read())
        print("   ✅ AI 分析成功！")
        return result['candidates'][0]['content']['parts'][0]['text']
    except urllib.error.HTTPError as e:
        error_info = e.read().decode()
        print(f"   ❌ API 錯誤 ({e.code}): {error_info}")
        sys.exit(1)
    except Exception as e:
        print(f"   ❌ 發生未知錯誤: {e}")
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
    print("☁️ [4/4] 正在將報告上傳至 Google Drive...")
    creds_json = json.loads(os.environ.get('GDRIVE_CREDENTIALS'))
    folder_id = os.environ.get('GDRIVE_FOLDER_ID').strip()
    
    creds = service_account.Credentials.from_service_account_info(
        creds_json, scopes=['https://www.googleapis.com/auth/drive.file']
    )
    service = build('drive', 'v3', credentials=creds)
    
    file_metadata = {'name': filename, 'parents': [folder_id]}
    media = MediaFileUpload(filename, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
    
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    print(f"✅ 上傳成功！Google Drive 檔案 ID: {file.get('id')}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python auto_analyst.py <IP地址>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    
    # 執行工作流
    vt_info = get_vt_data(target_ip)
    report_text = analyze_with_gemini(vt_info)
    doc_name = create_word_document(target_ip, report_text)
    upload_to_drive(doc_name)
    
    print("🎉 任務全數完成！請至您的 Google Drive 查看報告。")
