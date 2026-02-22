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
