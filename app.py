import os
import json
import hashlib
from datetime import datetime, timezone
import requests
from flask import Flask, render_template, request, jsonify

# 🔥 Firebase (Railway ENV based)
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)

# ── FIREBASE INIT (ENV SAFE) ─────────────────────────────
firebase_key = os.getenv("FIREBASE_KEY")

if not firebase_key:
    raise Exception("FIREBASE_KEY not set")

cred_dict = json.loads(firebase_key)

if not firebase_admin._apps:
    cred = credentials.Certificate(cred_dict)
    firebase_admin.initialize_app(cred)

db = firestore.client()

# ── IP INFO ──────────────────────────────────────────────

def get_ip_info(ip):
    clean_ip = ip.split(',')[0].strip()
    is_local = clean_ip in ('127.0.0.1', '::1', 'localhost')

    apis = [
        lambda: requests.get(
            f'http://ip-api.com/json/{("" if is_local else clean_ip)}'
            f'?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,query,proxy,hosting',
            timeout=5
        ).json(),
        lambda: requests.get(
            f'https://ipwho.is/{("" if is_local else clean_ip)}',
            timeout=5
        ).json(),
    ]

    for api in apis:
        try:
            data = api()
            if not data:
                continue

            return {
                'ip': data.get('query') or data.get('ip'),
                'city': data.get('city', 'Unknown'),
                'region': data.get('regionName') or data.get('region', ''),
                'country': data.get('country', 'Unknown'),
                'country_code': data.get('countryCode') or data.get('country_code', ''),
                'isp': data.get('isp', 'Unknown'),
                'org': data.get('org', ''),
                'timezone': data.get('timezone', 'Unknown'),
                'is_proxy': data.get('proxy', False),
                'is_hosting': data.get('hosting', False),
                'lat': data.get('lat'),
                'lon': data.get('lon'),
            }

        except Exception:
            continue

    return {
        'ip': clean_ip,
        'city': 'Unknown',
        'country': 'Unknown',
        'isp': 'Unknown',
        'timezone': 'Unknown',
        'is_proxy': False,
        'is_hosting': False
    }

# ── EXTRA FEATURES ───────────────────────────────────────

def detect_threats(info):
    threats = []

    if info.get("is_proxy"):
        threats.append("Proxy/VPN detected")

    if info.get("is_hosting"):
        threats.append("Datacenter network")

    if "cloud" in info.get("isp", "").lower():
        threats.append("Cloud provider network")

    return threats


def ip_reputation(info):
    score = 100

    if info.get("is_hosting"):
        score -= 40

    if info.get("is_proxy"):
        score -= 60

    return max(0, score)

# ── CLOUD SAVE ───────────────────────────────────────────

def save_scan(data):
    try:
        db.collection("scans").add({
            "ip": data.get("ip"),
            "city": data.get("city"),
            "country": data.get("country"),
            "isp": data.get("isp"),
            "vpn": data.get("is_proxy"),
            "timestamp": datetime.now(timezone.utc)
        })
    except Exception as e:
        print("Firestore error:", e)

# ── ROUTES ───────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/auto-scan')
def auto_scan():
    ip = request.headers.get('X-Forwarded-For') or request.remote_addr

    info = get_ip_info(ip)

    result = {
        "detected": info,
        "risk": 30,
        "level": "Moderate",
        "grade": "C",
        "threat_insights": detect_threats(info),
        "ip_reputation": ip_reputation(info),
        "scan_ts": datetime.now(timezone.utc).isoformat()
    }

    save_scan(info)

    return jsonify(result)


@app.route('/history')
def history():
    docs = db.collection("scans") \
        .order_by("timestamp", direction=firestore.Query.DESCENDING) \
        .limit(20).stream()

    data = [d.to_dict() for d in docs]

    return jsonify(data)


@app.route('/health')
def health():
    return jsonify({"status": "ok"})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
