import asyncio
import time
import httpx
import json
import os
import datetime
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES

from config import Config
from Pb2 import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2

app = Flask(__name__)
CORS(app)

app.json.sort_keys = False 

cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def format_timestamp(ts):
    try:
        if not ts or ts == "0": return "N/A"
        return datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %I:%M:%S %p')
    except:
        return str(ts)

def get_ban_duration(timestamp):
    """ব্যান হওয়ার পর থেকে বছর, মাস, সপ্তাহ, দিন, ঘণ্টা, মিনিট, সেকেন্ড ক্যালকুলেট করার ফাংশন"""
    if not timestamp or timestamp == "0":
        return "N/A"
    try:
        ts = int(timestamp)
        now = int(time.time())
        diff = now - ts
        
        if diff < 0:
            return "Account banned recently"

        years = diff // 31536000
        diff %= 31536000

        months = diff // 2592000
        diff %= 2592000

        weeks = diff // 604800
        diff %= 604800

        days = diff // 86400
        diff %= 86400

        hours = diff // 3600
        diff %= 3600

        minutes = diff // 60
        seconds = diff % 60

        parts = []
        # যেগুলোর মান 0 এর চেয়ে বেশি, সেগুলো আউটপুটে যুক্ত হবে
        if years > 0: parts.append(f"{years} Years")
        if months > 0: parts.append(f"{months} Months")
        if weeks > 0: parts.append(f"{weeks} Weeks")
        if days > 0: parts.append(f"{days} Days")
        if hours > 0: parts.append(f"{hours} Hours")
        if minutes > 0: parts.append(f"{minutes} Minutes")
        if seconds > 0 or not parts: parts.append(f"{seconds} Seconds")

        time_string = " ".join(parts)
        return f"Account banned {time_string} ago"
    except Exception:
        return "N/A"

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': Config.USER_AGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip", 
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    account = Config.get_account(region)
    token_val, open_id = await get_access_token(account)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(Config.MAIN_KEY, Config.MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': Config.USER_AGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 
        'Expect': "100-continue",
        'X-Unity-Version': Config.UNITY_VERSION, 
        'X-GA': "v1 1", 
        'ReleaseVersion': Config.RELEASE_VERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200
        }

async def initialize_tokens():
    tasks = [create_jwt(r) for r in Config.SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(Config.MAIN_KEY, Config.MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    headers = {
        'User-Agent': Config.USER_AGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 
        'Expect': "100-continue",
        'Authorization': token, 
        'X-Unity-Version': Config.UNITY_VERSION, 
        'X-GA': "v1 1",
        'ReleaseVersion': Config.RELEASE_VERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

async def check_ban_status_garena(uid):
    ban_url = f'https://ff.garena.com/api/antihack/check_banned?lang=en&uid={uid}'
    ban_headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'authority': 'ff.garena.com',
        'referer': 'https://ff.garena.com/en/support/',
        'x-requested-with': 'B6FksShzIgjfrYImLpTsadjS86sddhFH',
    }
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(ban_url, headers=ban_headers)
            data = resp.json()
            if data.get("status") == "success" and "data" in data:
                is_banned = data["data"].get("is_banned", 0)
                return is_banned
    except Exception:
        pass
    return 0

def format_response(player_data, is_banned):
    if not isinstance(player_data, dict):
        player_data = {}
        
    basic_info = player_data.get("basicInfo") or {}
    social_info = player_data.get("socialInfo") or {}

    last_login_timestamp = basic_info.get("lastLoginAt", "0")
    
    ban_message = "Account Banned ⛔" if is_banned else "Not Banned ✅"

    response_dict = {
        "DeveloperInfo": {
            "Developer": "Riduanul Islam",
            "TelegramBot": "https://t.me/RiduanFFBot",
            "TelegramChannel": "https://t.me/RiduanOfficialBD"
        },
        "BanCheckInfo": {
            "AccountName": basic_info.get("nickname", "N/A"),
            "AccountId": social_info.get("accountId", "N/A"),
            "AccountLevel": basic_info.get("level", 0),
            "AccountLikes": basic_info.get("liked", 0),
            "AccountRegion": basic_info.get("region", "N/A"),
            "Ban_Status": ban_message,
            "AccountCreateDate": format_timestamp(basic_info.get("createAt")),
            "AccountLastLoginDate": format_timestamp(last_login_timestamp)
        }
    }
    
    if is_banned:
        response_dict["BanCheckInfo"]["BanDuration"] = get_ban_duration(last_login_timestamp)

    return response_dict

@app.route('/')
def root_guide():
    return jsonify({
        "DeveloperInfo": {
            "Developer": "Riduanul Islam",
            "TelegramBot": "https://t.me/RiduanFFBot",
            "TelegramChannel": "https://t.me/RiduanOfficialBD"
        },
        "API_Usage_Guide": {
            "Project": "Free Fire Info & Ban Check API",
            "Status": "Active",
            "Message": "Welcome to Riduan FF Ban Check API! Use the endpoint below to fetch player ban status.",
            "API_Format": {
                "Check_Ban_Status": "/bancheck?uid=[uid]"
            },
            "ExampleUsage": "/bancheck?uid=2764669166"
        }
    }), 200

@app.route('/bancheck', methods=['GET'])
def get_account_and_ban_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    
    try:
        region = "ME"
        
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
        player_info_task = GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
        ban_status_task = check_ban_status_garena(uid)
        
        player_data, is_banned = loop.run_until_complete(asyncio.gather(player_info_task, ban_status_task))
        
        formatted = format_response(player_data, is_banned)
        return jsonify(formatted), 200
    
    except Exception as e:
        return jsonify({
            "error": "Failed to fetch data. Server error or invalid UID.",
            "details": str(e)
        }), 500

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
        loop.run_until_complete(initialize_tokens())
        return jsonify({'message': 'Tokens refreshed for all regions.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

if __name__ == '__main__':
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(initialize_tokens())
    except:
        pass
        
    app.run(host='0.0.0.0', port=Config.PORT, debug=Config.DEBUG)
