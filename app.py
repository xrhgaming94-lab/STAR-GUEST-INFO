# INFO API SRC BYY :
# POWERED BY : @STAR_GMR
# CHANNEL : @STAR_METHODE
import asyncio
import os
import time
import httpx
import json
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Settings ===

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB54"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === Flask App Setup ===

app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
uid_region_cache = {}

# === Helper Functions ===

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

# === Token Generation with Dynamic Credentials (No Hardcoded) ===

async def get_access_token(guest_uid: str, password: str):
    """Get access token using provided guest UID and password"""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"uid={guest_uid}&password={password}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str, guest_uid: str, password: str):
    """Create JWT token using provided credentials"""
    token_val, open_id = await get_access_token(guest_uid, password)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1",
               'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
        # Store token with region and credentials as key
        cache_key = f"{region}_{guest_uid}"
        cached_tokens[cache_key] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200,
            'guest_uid': guest_uid,
            'password': password
        }
        return cached_tokens[cache_key]

async def get_token_info(region: str, guest_uid: str, password: str) -> Tuple[str,str,str]:
    """Get token info for specific credentials"""
    cache_key = f"{region}_{guest_uid}"
    info = cached_tokens.get(cache_key)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    # Create new token with provided credentials
    await create_jwt(region, guest_uid, password)
    info = cached_tokens[cache_key]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint, guest_uid, password):
    """Get account information with dynamic credentials"""
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region, guest_uid, password)
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue",
               'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
               'ReleaseVersion': RELEASEVERSION}
    async with httpx.AsyncClient() as client:
        resp = await client.post(server+endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

# === Caching Decorator ===

def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            # Include guest params in cache key
            args = request.args
            key = (request.path, tuple(args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# === Flask Routes ===

@app.route('/accinfo')
@cached_endpoint()
def get_account_info():
    uid = request.args.get('uid')
    guest_uid = request.args.get('guest_uid')
    password = request.args.get('password')
    
    # Validation - sab mandatory hai
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    
    if not guest_uid:
        return jsonify({"error": "Please provide guest_uid."}), 400
    
    if not password:
        return jsonify({"error": "Please provide password."}), 400

    # Check cached region for UID
    if uid in uid_region_cache:
        try:
            return_data = asyncio.run(GetAccountInformation(
                uid, "7", uid_region_cache[uid], "/GetPlayerPersonalShow", 
                guest_uid, password
            ))
            formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
            return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
        except:
            pass  # fallback to testing all regions

    for region in SUPPORTED_REGIONS:
        try:
            return_data = asyncio.run(GetAccountInformation(
                uid, "7", region, "/GetPlayerPersonalShow",
                guest_uid, password
            ))
            uid_region_cache[uid] = region
            formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
            return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
        except:
            continue

    return jsonify({"error": "UID not found in any region."}), 404

@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    # Yeh endpoint ab sirf specific guest_uid aur password ke tokens refresh karega
    guest_uid = request.args.get('guest_uid')
    password = request.args.get('password')
    
    if not guest_uid or not password:
        return jsonify({"error": "Please provide guest_uid and password to refresh."}), 400
    
    try:
        # Refresh token for all regions with these credentials
        for region in SUPPORTED_REGIONS:
            asyncio.run(create_jwt(region, guest_uid, password))
        return jsonify({'message': f'Tokens refreshed for guest_uid: {guest_uid} in all regions.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

@app.route('/refresh_all', methods=['GET','POST'])
def refresh_all_tokens_endpoint():
    # Yeh endpoint sabhi cached credentials ke tokens refresh karega
    try:
        tasks = []
        for key in list(cached_tokens.keys()):
            if '_' in key:
                region, guest_uid = key.split('_', 1)
                password = cached_tokens[key].get('password')
                if password:
                    tasks.append(create_jwt(region, guest_uid, password))
        
        if tasks:
            asyncio.run(asyncio.gather(*tasks))
            return jsonify({'message': f'All {len(tasks)} tokens refreshed.'}), 200
        else:
            return jsonify({'message': 'No tokens to refresh.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

# === Startup ===

# Startup mein kuch initialize nahi karenge kyunki ab sab dynamic hai
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
# INFO API SRC BYY :
# POWERED BY : @STAR_GMR
# CHANNEL : @STAR_METHODE
