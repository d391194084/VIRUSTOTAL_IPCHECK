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
    print("🧠 [2/4] 正在透過原生 REST API 將數據傳送給 Gemini 進行深度分析...")
    
    api_key = os.environ.get('GEMINI_API_KEY')
    if not api_key:
        print("❌ 錯誤：找不到 GEMINI_API_KEY。")
        sys.exit(1)
        
    api_key = api_key.strip()
    
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
    
    # 🔥 放棄不準確的 ListModels，改用「硬闖」清單
    # 這裡的順序是精心安排的：從目前最穩定、新用戶必定開放的模型開始
    models_to_try = [
        "gemini-1.5-flash",       # 目前全球最穩定且新用戶必備的標準版
        "gemini-1.5-flash-8b",    # 限制極少的輕量極速版
        "gemini-1.5-pro",         # 若有權限則能產出最強分析
        "gemini-pro"              # 最舊但 100% 絕對不會被擋的 1.0 版
    ]
    
    for model_name in models_to_try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
        print(f"   ⏳ 正在嘗試使用模型: {model_name} ...")
        
        req = urllib.request.Request(url, data=data)
        req.add_header('Content-Type', 'application/json')
        
        try:
            response = urllib.request.urlopen(req)
            result = json.loads(response.read())
            print(f"   ✅ 成功！已使用 {model_name} 產出分析報告。")
            return result['candidates'][0]['content']['parts'][0]['text']
        
        except urllib.error.HTTPError as e:
            try:
                error_info = json.loads(e.read().decode())
                error_msg = error_info.get('error', {}).get('message', '未知原因')
            except:
                error_msg = str(e)
            print(f"   ⚠️ 此模型不可用 ({e.code}): {error_msg}，自動切換下一個...")
            continue
        except Exception as e:
            print(f"   ⚠️ 發生未知錯誤: {e}，自動切換下一個...")
            continue

    # 如果連最基礎的 gemini-pro 都失敗，才是真的出大問題
    print("❌ 致命錯誤：所有備援模型皆被 Google 拒絕。請確認您的 API Key 狀態。")
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
