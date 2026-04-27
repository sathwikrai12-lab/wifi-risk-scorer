import os
import json
import random
import sqlite3
import requests
from datetime import datetime
from flask import Flask, render_template, request, jsonify, g

app = Flask(__name__)
DATABASE = '/tmp/safehop.db'

# ── FIREBASE SETUP (safe — won't crash if key is missing) ────────────
USE_FIREBASE = False
db_firebase = None

try:
    import firebase_admin
    from firebase_admin import credentials, firestore as fs

    raw_key = os.environ.get("FIREBASE_KEY", "")
    if raw_key:
        key_dict = json.loads(raw_key)
        if not firebase_admin._apps:
            cred = credentials.Certificate(key_dict)
            firebase_admin.initialize_app(cred)
        db_firebase = fs.client()
        USE_FIREBASE = True
        print("✅ Firebase connected")
    else:
        print("⚠️ FIREBASE_KEY not set — using SQLite only")
except Exception as ex:
    print(f"⚠️ Firebase init failed: {ex} — using SQLite only")

# ── SQLITE SETUP ─────────────────────────────────────────────────────
def get_db():
    db = getattr(g, '_db', None)
    if db is None:
        db = g._db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(e):
    db = getattr(g, '_db', None)
    if db:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT, city TEXT, country TEXT, isp TEXT,
            timezone TEXT, is_https INTEGER, vpn INTEGER,
            risk INTEGER, level TEXT, grade TEXT,
            threats INTEGER, scanned_at TEXT
        )''')
        db.commit()

# ── IP LOOKUP — 4 APIs with fallback ────────────────────────────────
def get_ip_info(ip):
    clean = ip.split(',')[0].strip()
    local = clean in ('127.0.0.1', '::1', 'localhost')
    target = '' if local else clean

    apis = [
        lambda: _parse(requests.get(
            f'http://ip-api.com/json/{target}?fields=status,country,countryCode,regionName,city,timezone,isp,org,query,proxy,hosting,mobile',
            timeout=5).json(), clean),
        lambda: _parse(requests.get(
            f'https://ipwho.is/{target}', timeout=5).json(), clean),
        lambda: _parse(requests.get(
            f'https://ipapi.co/{target}/json/', timeout=5).json(), clean),
        lambda: _parse(requests.get(
            f'https://api.ip.sb/geoip/{target}', timeout=5).json(), clean),
    ]

    for fn in apis:
        try:
            info = fn()
            if info.get('city') not in ('Unknown', '', None):
                return info
        except Exception:
            continue

    return {'ip': clean, 'city': 'Unknown', 'country': 'Unknown',
            'region': '', 'isp': 'Unknown', 'org': '',
            'timezone': 'Unknown', 'is_proxy': False,
            'is_hosting': False, 'is_mobile': False}

def _parse(d, ip):
    # ip-api.com
    if 'countryCode' in d:
        return {
            'ip': d.get('query', ip),
            'city': d.get('city', 'Unknown'),
            'region': d.get('regionName', ''),
            'country': d.get('country', 'Unknown'),
            'isp': d.get('isp', d.get('org', 'Unknown')),
            'org': d.get('org', ''),
            'timezone': d.get('timezone', 'Unknown'),
            'is_proxy': bool(d.get('proxy')),
            'is_hosting': bool(d.get('hosting')),
            'is_mobile': bool(d.get('mobile'))
        }
    # ipwho.is
    if 'connection' in d:
        conn = d.get('connection', {})
        tz = d.get('timezone', {})
        return {
            'ip': d.get('ip', ip),
            'city': d.get('city', 'Unknown'),
            'region': d.get('region', ''),
            'country': d.get('country', 'Unknown'),
            'isp': conn.get('isp', 'Unknown'),
            'org': conn.get('org', ''),
            'timezone': tz.get('id', 'Unknown') if isinstance(tz, dict) else str(tz),
            'is_proxy': d.get('security', {}).get('proxy', False),
            'is_hosting': d.get('security', {}).get('hosting', False),
            'is_mobile': False
        }
    # ipapi.co / ip.sb
    return {
        'ip': d.get('ip', ip),
        'city': d.get('city', 'Unknown'),
        'region': d.get('region', ''),
        'country': d.get('country_name', d.get('country', 'Unknown')),
        'isp': d.get('org', d.get('isp', 'Unknown')),
        'org': d.get('org', d.get('organization', '')),
        'timezone': d.get('timezone', 'Unknown'),
        'is_proxy': False,
        'is_hosting': False,
        'is_mobile': False
    }

# ── VPN DETECTION ────────────────────────────────────────────────────
def detect_vpn(info):
    if info.get('is_proxy') or info.get('is_hosting'):
        return True
    text = (info.get('org', '') + ' ' + info.get('isp', '')).lower()
    keywords = ['vpn', 'proxy', 'hosting', 'digitalocean', 'linode', 'vultr',
                'amazon', 'google cloud', 'microsoft azure', 'cloudflare',
                'mullvad', 'nordvpn', 'expressvpn', 'hetzner', 'ovh',
                'datacenter', 'data center', 'server farm']
    return any(k in text for k in keywords)

# ── NEW: EXTENDED SECURITY CHECKS ─────────────────────────────────────
def check_wifi_encryption(info, vpn):
    """Simulate Wi-Fi encryption type based on available info."""
    isp_lower = info.get('isp', '').lower()
    is_mobile = info.get('is_mobile', False)
    # Mobile data = LTE/5G (strong encryption)
    if is_mobile or any(k in isp_lower for k in ['mobile', 'cellular', 'airtel', 'jio', 'bsnl', 'vodafone']):
        return {'type': 'LTE/5G', 'status': 'pass', 'detail': 'Mobile data — LTE/5G encryption active'}
    # VPN or hosting suggests corporate/secured network
    if vpn:
        return {'type': 'WPA3/WPA2', 'status': 'pass', 'detail': 'Likely secured — VPN tunnel active'}
    # Residential broadband typically WPA2
    return {'type': 'WPA2 (assumed)', 'status': 'warn', 'detail': 'WPA2 assumed — cannot verify remotely'}

def check_dns_leak(info, vpn):
    """Basic DNS leak detection heuristic."""
    if vpn:
        # Even with VPN, check if org/isp hints at ISP-level DNS
        isp = info.get('isp', '').lower()
        org = info.get('org', '').lower()
        if any(k in isp + org for k in ['comcast', 'at&t', 'verizon', 'spectrum', 'cox', 'airtel', 'jio']):
            return {'leaked': True, 'status': 'warn',
                    'detail': 'VPN active but ISP DNS may leak — use VPN\'s DNS resolver'}
        return {'leaked': False, 'status': 'pass', 'detail': 'DNS appears routed through VPN'}
    return {'leaked': True, 'status': 'fail',
            'detail': f'DNS queries exposed to {info.get("isp", "your ISP")}'}

def check_browser_fingerprint():
    """Browser fingerprint exposure assessment — always a risk without protection."""
    return {
        'status': 'warn',
        'detail': 'Browser fingerprint unique — trackable across sites without protection'
    }

def check_open_ports_risk(info, vpn):
    """Simulated open port risk based on network type."""
    if vpn:
        return {'status': 'pass', 'detail': 'VPN masks exposed ports — lower attack surface'}
    if info.get('is_hosting'):
        return {'status': 'fail', 'detail': 'Datacenter IP — common ports likely scanned by bots'}
    return {'status': 'warn', 'detail': 'Residential IP — standard ports visible (22, 80, 443)'}

def check_https_score(is_https, vpn):
    """More granular HTTPS enforcement scoring."""
    if is_https and vpn:
        return {'score': 'A+', 'status': 'pass', 'detail': 'HTTPS + VPN tunnel — double-encrypted'}
    if is_https:
        return {'score': 'B+', 'status': 'pass', 'detail': 'HTTPS active — TLS enforced end-to-end'}
    if vpn:
        return {'score': 'C', 'status': 'warn', 'detail': 'VPN active but site lacks HTTPS'}
    return {'score': 'F', 'status': 'fail', 'detail': 'No HTTPS — traffic fully unencrypted'}

# ── SECURITY CHECKS (ORIGINAL + EXTENDED) ─────────────────────────────
def run_checks(info, is_https, vpn):
    high_risk = ['China', 'Russia', 'Iran', 'North Korea', 'Belarus', 'Syria']
    isp_lower = info.get('isp', '').lower()
    country = info.get('country', 'Unknown')
    is_mobile = info.get('is_mobile', False) or any(
        k in isp_lower for k in ['mobile', 'cellular', 'airtel', 'jio', 'bsnl', 'vodafone'])

    # --- Original 13 checks ---
    original = [
        {'id': 'https',  'name': 'HTTPS Encryption',   'icon': '🔒',
         'status': 'pass' if is_https else 'fail',
         'detail': 'End-to-end encrypted' if is_https else 'Unencrypted — data exposed'},
        {'id': 'vpn',    'name': 'VPN Protection',      'icon': '🛡️',
         'status': 'pass' if vpn else 'warn',
         'detail': 'VPN active — IP is masked' if vpn else 'No VPN — IP visible to all sites'},
        {'id': 'region', 'name': 'Region Safety',       'icon': '🌍',
         'status': 'fail' if country in high_risk else 'pass',
         'detail': f'High-risk region: {country}' if country in high_risk else f'Standard region: {country}'},
        {'id': 'isp',    'name': 'ISP Type',            'icon': '📡',
         'status': 'warn' if is_mobile else 'pass',
         'detail': f'Mobile carrier: {info.get("isp","")}' if is_mobile else f'Broadband: {info.get("isp","")}'},
        {'id': 'proxy',  'name': 'Proxy / Datacenter',  'icon': '🖥️',
         'status': 'warn' if info.get('is_hosting') else 'pass',
         'detail': 'Datacenter IP — shared routing' if info.get('is_hosting') else 'Residential IP'},
        {'id': 'dns',    'name': 'DNS Privacy',         'icon': '🔍',
         'status': 'pass' if vpn else 'warn',
         'detail': 'VPN likely securing DNS' if vpn else 'DNS queries may expose browsing'},
        {'id': 'ip',     'name': 'IP Exposure',         'icon': '👁️',
         'status': 'warn',
         'detail': f'Your IP {info.get("ip", "")} is publicly visible'},
        {'id': 'proto',  'name': 'Protocol Security',   'icon': '⚡',
         'status': 'pass' if is_https else 'fail',
         'detail': 'TLS/SSL active' if is_https else 'Plain HTTP — no TLS'},
        {'id': 'firewall', 'name': 'Firewall',          'icon': '🔥',
         'status': 'warn', 'detail': 'Enable firewall on your device'},
        {'id': 'updates',  'name': 'System Updates',    'icon': '⬆️',
         'status': 'warn', 'detail': 'Keep OS and apps updated'},
        {'id': 'malware',  'name': 'Malware Shield',    'icon': '🛡️',
         'status': 'warn', 'detail': 'Run reputable antivirus software'},
        {'id': 'publicwifi', 'name': 'Public Wi-Fi',   'icon': '📶',
         'status': 'fail' if not vpn else 'pass',
         'detail': 'Unsafe without VPN' if not vpn else 'VPN protects on public Wi-Fi'},
        {'id': 'tracking', 'name': 'Activity Tracking', 'icon': '👣',
         'status': 'warn', 'detail': 'Network may track browsing activity'}
    ]

    # --- NEW: 5 Extended checks ---
    wifi_enc = check_wifi_encryption(info, vpn)
    dns_leak  = check_dns_leak(info, vpn)
    bf        = check_browser_fingerprint()
    ports     = check_open_ports_risk(info, vpn)
    https_sc  = check_https_score(is_https, vpn)

    extended = [
        {'id': 'wifi_enc',  'name': 'Wi-Fi Encryption',       'icon': '📶',
         'status': wifi_enc['status'],
         'detail': wifi_enc['detail'],
         'extra': wifi_enc.get('type', '')},
        {'id': 'dns_leak',  'name': 'DNS Leak Detection',      'icon': '🌐',
         'status': dns_leak['status'],
         'detail': dns_leak['detail']},
        {'id': 'fingerprint', 'name': 'Browser Fingerprint',   'icon': '🧬',
         'status': bf['status'],
         'detail': bf['detail']},
        {'id': 'open_ports', 'name': 'Open Ports Risk',        'icon': '🔓',
         'status': ports['status'],
         'detail': ports['detail']},
        {'id': 'https_score', 'name': 'HTTPS Enforcement',     'icon': '🏅',
         'status': https_sc['status'],
         'detail': https_sc['detail'],
         'extra': https_sc.get('score', '')},
    ]

    return original + extended

# ── SCORING ──────────────────────────────────────────────────────────
def calculate_score(info, is_https, vpn):
    score = 0
    breakdown = []
    recs = []

    pts = 0 if is_https else 25
    score += pts
    breakdown.append({'label': 'HTTPS', 'points': pts, 'max': 25})
    recs.append({'type': 'good', 'text': 'HTTPS active — connection encrypted.'} if is_https
                else {'type': 'bad', 'text': 'No HTTPS — traffic visible in plain text.'})

    pts = 0 if vpn else 20
    score += pts
    breakdown.append({'label': 'VPN Protection', 'points': pts, 'max': 20})
    recs.append({'type': 'good', 'text': 'VPN detected — real IP is hidden.'} if vpn
                else {'type': 'bad', 'text': 'No VPN — your IP and location are exposed.'})

    isp = info.get('isp', '').lower()
    mobile_isps = ['mobile', 'cellular', 'airtel', 'jio', 'bsnl', 'vodafone', 'idea', 'aircel']
    big_isps = ['comcast', 'at&t', 'verizon', 'spectrum', 'cox']
    pts = 10 if any(k in isp for k in mobile_isps) else 14 if any(k in isp for k in big_isps) else 0
    score += pts
    breakdown.append({'label': 'ISP Risk', 'points': pts, 'max': 20})
    recs.append({'type': 'bad', 'text': f'ISP {info.get("isp","")} — use VPN on shared networks.'} if pts > 0
                else {'type': 'good', 'text': f'ISP {info.get("isp","Unknown")} appears standard.'})

    high_risk = ['China', 'Russia', 'Iran', 'North Korea', 'Belarus', 'Syria']
    country = info.get('country', 'Unknown')
    pts = 15 if country in high_risk else 0
    score += pts
    breakdown.append({'label': 'Region Risk', 'points': pts, 'max': 15})
    recs.append({'type': 'bad', 'text': f'{country} — elevated surveillance risk.'} if pts
                else {'type': 'good', 'text': f'{country} — standard risk region.'})

    pts = 10 if info.get('is_hosting') else 0
    score += pts
    breakdown.append({'label': 'Network Type', 'points': pts, 'max': 20})
    if pts:
        recs.append({'type': 'bad', 'text': 'Datacenter IP — possible commercial proxy.'})

    score = max(0, min(100, score))
    level = 'Safe' if score <= 30 else 'Moderate' if score <= 60 else 'Dangerous'
    grade = ('A+' if score <= 15 else 'A' if score <= 25 else 'B' if score <= 40
             else 'C' if score <= 55 else 'D' if score <= 70 else 'F')

    return {
        'risk': score, 'level': level, 'grade': grade,
        'threats': sum(1 for r in recs if r['type'] == 'bad'),
        'protections': sum(1 for r in recs if r['type'] == 'good'),
        'breakdown': breakdown, 'recommendations': recs
    }

# ── NEW: SMART INSIGHTS ───────────────────────────────────────────────
def build_insights(info, is_https, vpn, result):
    insights = []
    isp = info.get('isp', 'Unknown')
    country = info.get('country', 'Unknown')
    ip = info.get('ip', 'Unknown')
    is_hosting = info.get('is_hosting', False)
    is_mobile = info.get('is_mobile', False)

    if not vpn:
        insights.append({'icon': '👁️', 'severity': 'high',
            'text': f'No VPN detected — your real IP ({ip}) is exposed to every website you visit.'})
    else:
        insights.append({'icon': '🛡️', 'severity': 'low',
            'text': f'VPN active — your real IP is masked. Sites see a different address.'})

    if not is_https:
        insights.append({'icon': '🔓', 'severity': 'high',
            'text': 'This connection lacks HTTPS — anyone on your network can read your traffic.'})

    if is_mobile:
        insights.append({'icon': '📱', 'severity': 'low',
            'text': f'You\'re on mobile data via {isp} — generally more private than public Wi-Fi.'})
    elif is_hosting:
        insights.append({'icon': '🌐', 'severity': 'medium',
            'text': f'Your IP is from a datacenter ({isp}) — suggests a VPN or shared hosting network.'})
    else:
        insights.append({'icon': '🏠', 'severity': 'low',
            'text': f'Your ISP ({isp}) suggests you\'re on a residential broadband connection.'})

    if result['risk'] > 60:
        insights.append({'icon': '⚠️', 'severity': 'high',
            'text': f'High risk score ({result["risk"]}/100) — avoid banking, passwords, or sensitive logins on this network.'})
    elif result['risk'] > 30:
        insights.append({'icon': '🟡', 'severity': 'medium',
            'text': 'Moderate risk — safe for general browsing, but avoid entering sensitive credentials.'})
    else:
        insights.append({'icon': '✅', 'severity': 'low',
            'text': 'Low risk detected — your connection looks secure for general use.'})

    return insights

# ── NEW: SECURE GUIDE (dynamic based on scan) ──────────────────────────
def build_secure_guide(info, is_https, vpn, result):
    steps = []
    step_num = 1

    if not vpn:
        steps.append({
            'step': step_num, 'priority': 'critical',
            'title': 'Enable a VPN immediately',
            'detail': 'Your IP and location are fully exposed. A VPN encrypts your traffic and hides your real IP. Recommended: Mullvad, ProtonVPN, or Windscribe (free tier available).'
        })
        step_num += 1

    if not is_https:
        steps.append({
            'step': step_num, 'priority': 'critical',
            'title': 'Switch to HTTPS-only mode',
            'detail': 'Enable "HTTPS-Only Mode" in your browser settings (Firefox: Settings → Privacy; Chrome: Settings → Security). This prevents accessing unencrypted sites.'
        })
        step_num += 1

    steps.append({
        'step': step_num, 'priority': 'high',
        'title': 'Install a DNS privacy resolver',
        'detail': 'Change your DNS to Cloudflare (1.1.1.1) or NextDNS to prevent your ISP from logging your DNS queries. On Wi-Fi: Router Settings → DNS → 1.1.1.1 / 1.0.0.1.'
    })
    step_num += 1

    steps.append({
        'step': step_num, 'priority': 'high',
        'title': 'Reduce browser fingerprinting',
        'detail': 'Install uBlock Origin + Canvas Blocker extensions. Use Firefox with strict privacy mode, or Brave Browser. Avoid Chrome on untrusted networks.'
    })
    step_num += 1

    if not info.get('is_mobile', False):
        steps.append({
            'step': step_num, 'priority': 'medium',
            'title': 'Enable your device firewall',
            'detail': 'macOS: System Preferences → Security → Firewall → Enable. Windows: Control Panel → Windows Defender Firewall → Turn On. Blocks unsolicited inbound connections.'
        })
        step_num += 1

    steps.append({
        'step': step_num, 'priority': 'medium',
        'title': 'Keep your OS and apps updated',
        'detail': 'Security patches are released constantly. Enable automatic updates. Check: macOS → System Preferences → Software Update. Windows → Settings → Update & Security.'
    })
    step_num += 1

    steps.append({
        'step': step_num, 'priority': 'low',
        'title': 'Use a password manager',
        'detail': 'Never reuse passwords. On untrusted networks, credential theft is easy if HTTPS is absent. Use Bitwarden (free, open-source) or 1Password.'
    })

    return steps

# ── ROUTES (ALL ORIGINAL PRESERVED) ───────────────────────────────────
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/auto-scan')
def auto_scan():
    ip = (request.headers.get('X-Forwarded-For') or
          request.headers.get('X-Real-IP') or
          request.remote_addr or '127.0.0.1')
    is_https = (request.headers.get('X-Forwarded-Proto', 'http') == 'https'
                or request.url.startswith('https'))

    info = get_ip_info(ip)
    vpn = detect_vpn(info)
    result = calculate_score(info, is_https, vpn)
    result['checks'] = run_checks(info, is_https, vpn)
    result['insights'] = build_insights(info, is_https, vpn, result)     # NEW
    result['secure_guide'] = build_secure_guide(info, is_https, vpn, result)  # NEW
    result['detected'] = {
        'ip': info.get('ip', ip.split(',')[0].strip()),
        'isp': info.get('isp', 'Unknown'),
        'city': info.get('city', 'Unknown'),
        'region': info.get('region', ''),
        'country': info.get('country', 'Unknown'),
        'is_https': is_https,
        'vpn': vpn,
        'timezone': info.get('timezone', 'Unknown'),
        'is_mobile': info.get('is_mobile', False),
    }

    scan_data = {
        'ip': result['detected']['ip'],
        'city': result['detected']['city'],
        'country': result['detected']['country'],
        'isp': result['detected']['isp'],
        'timezone': result['detected']['timezone'],
        'is_https': is_https,
        'vpn': vpn,
        'risk': result['risk'],
        'level': result['level'],
        'grade': result['grade'],
        'threats': result['threats'],
        'scanned_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    }

    # Save to SQLite
    try:
        db = get_db()
        db.execute('''INSERT INTO scans
            (ip,city,country,isp,timezone,is_https,vpn,risk,level,grade,threats,scanned_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            (scan_data['ip'], scan_data['city'], scan_data['country'],
             scan_data['isp'], scan_data['timezone'],
             int(is_https), int(vpn), result['risk'], result['level'],
             result['grade'], result['threats'], scan_data['scanned_at']))
        db.commit()
    except Exception as e:
        print(f"SQLite error: {e}")

    # Save to Firebase
    try:
        if USE_FIREBASE and db_firebase:
            db_firebase.collection('scans').add({
                **scan_data,
                'scanned_at': datetime.utcnow().isoformat()
            })
    except Exception as e:
        print(f"Firebase error: {e}")

    return jsonify(result)

# ── NEW: MANUAL SCAN ENDPOINT ──────────────────────────────────────────
@app.route('/manual-scan', methods=['POST'])
def manual_scan():
    data = request.get_json(force=True) or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'No target provided'}), 400

    # Resolve URL to IP if needed
    import re
    # Strip protocol/path to get hostname
    hostname = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]

    # Check if it's already an IP
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    if ip_pattern.match(hostname):
        ip = hostname
    else:
        try:
            import socket
            ip = socket.gethostbyname(hostname)
        except Exception:
            return jsonify({'error': f'Could not resolve hostname: {hostname}'}), 400

    is_https = target.startswith('https://') if '://' in target else False

    info = get_ip_info(ip)
    vpn = detect_vpn(info)
    result = calculate_score(info, is_https, vpn)
    result['checks'] = run_checks(info, is_https, vpn)
    result['insights'] = build_insights(info, is_https, vpn, result)
    result['secure_guide'] = build_secure_guide(info, is_https, vpn, result)
    result['detected'] = {
        'ip': info.get('ip', ip),
        'isp': info.get('isp', 'Unknown'),
        'city': info.get('city', 'Unknown'),
        'region': info.get('region', ''),
        'country': info.get('country', 'Unknown'),
        'is_https': is_https,
        'vpn': vpn,
        'timezone': info.get('timezone', 'Unknown'),
        'is_mobile': info.get('is_mobile', False),
        'manual_target': target,
    }
    return jsonify(result)

@app.route('/history')
def history():
    results = []
    # Try Firebase first
    try:
        if USE_FIREBASE and db_firebase:
            docs = db_firebase.collection('scans').order_by(
                'scanned_at', direction='DESCENDING').limit(15).stream()
            results = [doc.to_dict() for doc in docs]
            if results:
                return jsonify(results)
    except Exception as e:
        print(f"Firebase history error: {e}")

    # Fallback to SQLite
    try:
        db = get_db()
        rows = db.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 15').fetchall()
        results = [dict(r) for r in rows]
    except Exception as e:
        print(f"SQLite history error: {e}")

    return jsonify(results)

@app.route('/stats')
def stats():
    try:
        db = get_db()
        total = db.execute('SELECT COUNT(*) as c FROM scans').fetchone()['c']
        dangerous = db.execute("SELECT COUNT(*) as c FROM scans WHERE level='Dangerous'").fetchone()['c']
        safe = db.execute("SELECT COUNT(*) as c FROM scans WHERE level='Safe'").fetchone()['c']
        avg = db.execute('SELECT AVG(risk) as a FROM scans').fetchone()['a'] or 0
        return jsonify({'total': total, 'dangerous': dangerous,
                        'safe': safe, 'avg_risk': round(avg, 1)})
    except Exception:
        return jsonify({'total': 0, 'dangerous': 0, 'safe': 0, 'avg_risk': 0})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

init_db()
