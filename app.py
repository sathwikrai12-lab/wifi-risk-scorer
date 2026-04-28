import os
import json
import sqlite3
import requests
from datetime import datetime
from flask import Flask, render_template, request, jsonify, g

app = Flask(__name__)
DATABASE = '/tmp/safehop.db'

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
        print("Firebase connected")
    else:
        print("No FIREBASE_KEY - using SQLite only")
except Exception as ex:
    print("Firebase init failed: " + str(ex))

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

def get_ip_info(ip):
    clean = ip.split(',')[0].strip()
    local = clean in ('127.0.0.1', '::1', 'localhost')
    target = '' if local else clean

    apis = [
        lambda: _parse(requests.get(
            'http://ip-api.com/json/' + target + '?fields=status,country,countryCode,regionName,city,timezone,isp,org,query,proxy,hosting,mobile',
            timeout=5).json(), clean),
        lambda: _parse(requests.get(
            'https://ipwho.is/' + target, timeout=5).json(), clean),
        lambda: _parse(requests.get(
            'https://ipapi.co/' + target + '/json/', timeout=5).json(), clean),
        lambda: _parse(requests.get(
            'https://api.ip.sb/geoip/' + target, timeout=5).json(), clean),
    ]

    for fn in apis:
        try:
            info = fn()
            if info.get('city') not in ('Unknown', '', None):
                return info
        except Exception:
            continue

    return {
        'ip': clean, 'city': 'Unknown', 'country': 'Unknown',
        'region': '', 'isp': 'Unknown', 'org': '',
        'timezone': 'Unknown', 'is_proxy': False,
        'is_hosting': False, 'is_mobile': False
    }

def _parse(d, ip):
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

def detect_vpn(info):
    if info.get('is_proxy') or info.get('is_hosting'):
        return True
    text = (info.get('org', '') + ' ' + info.get('isp', '')).lower()
    keywords = [
        'vpn', 'proxy', 'hosting', 'digitalocean', 'linode', 'vultr',
        'amazon', 'google cloud', 'microsoft azure', 'cloudflare',
        'mullvad', 'nordvpn', 'expressvpn', 'hetzner', 'ovh',
        'datacenter', 'data center', 'server farm'
    ]
    return any(k in text for k in keywords)

def run_checks(info, is_https, vpn):
    high_risk = ['China', 'Russia', 'Iran', 'North Korea', 'Belarus', 'Syria']
    isp_lower = info.get('isp', '').lower()
    country = info.get('country', 'Unknown')
    is_mobile = info.get('is_mobile', False) or any(
        k in isp_lower for k in ['mobile', 'cellular', 'airtel', 'jio', 'bsnl', 'vodafone']
    )

    return [
        {
            'id': 'https', 'name': 'HTTPS Encryption', 'icon': '🔒',
            'status': 'pass' if is_https else 'fail',
            'detail': 'End-to-end encrypted' if is_https else 'Unencrypted - data exposed',
            'extra': 'TLS active' if is_https else 'No TLS'
        },
        {
            'id': 'vpn', 'name': 'VPN Protection', 'icon': 'shield',
            'status': 'pass' if vpn else 'warn',
            'detail': 'VPN active - IP is masked' if vpn else 'No VPN - IP visible to all sites',
            'extra': ''
        },
        {
            'id': 'region', 'name': 'Region Safety', 'icon': '🌍',
            'status': 'fail' if country in high_risk else 'pass',
            'detail': 'High-risk region: ' + country if country in high_risk else 'Standard region: ' + country,
            'extra': 'high risk' if country in high_risk else ''
        },
        {
            'id': 'isp', 'name': 'ISP Type', 'icon': '📡',
            'status': 'warn' if is_mobile else 'pass',
            'detail': 'Mobile carrier: ' + info.get('isp', '') if is_mobile else 'Broadband: ' + info.get('isp', ''),
            'extra': 'mobile' if is_mobile else 'broadband'
        },
        {
            'id': 'proxy', 'name': 'Proxy / Datacenter', 'icon': '🖥',
            'status': 'warn' if info.get('is_hosting') else 'pass',
            'detail': 'Datacenter IP - shared routing' if info.get('is_hosting') else 'Residential IP',
            'extra': 'datacenter' if info.get('is_hosting') else ''
        },
        {
            'id': 'dns', 'name': 'DNS Privacy', 'icon': '🔍',
            'status': 'pass' if vpn else 'warn',
            'detail': 'VPN likely securing DNS' if vpn else 'DNS queries may expose browsing',
            'extra': ''
        },
        {
            'id': 'ip', 'name': 'IP Exposure', 'icon': '👁',
            'status': 'warn',
            'detail': 'Your IP ' + info.get('ip', '') + ' is publicly visible',
            'extra': ''
        },
        {
            'id': 'proto', 'name': 'Protocol Security', 'icon': '⚡',
            'status': 'pass' if is_https else 'fail',
            'detail': 'TLS/SSL active' if is_https else 'Plain HTTP - no TLS',
            'extra': ''
        },
    ]

def calculate_score(info, is_https, vpn):
    score = 0
    breakdown = []
    recs = []

    pts = 0 if is_https else 25
    score += pts
    breakdown.append({'label': 'HTTPS', 'points': pts, 'max': 25})
    if is_https:
        recs.append({'type': 'good', 'text': 'HTTPS active - connection encrypted.'})
    else:
        recs.append({'type': 'bad', 'text': 'No HTTPS - traffic visible in plain text.'})

    pts = 0 if vpn else 20
    score += pts
    breakdown.append({'label': 'VPN Protection', 'points': pts, 'max': 20})
    if vpn:
        recs.append({'type': 'good', 'text': 'VPN detected - real IP is hidden.'})
    else:
        recs.append({'type': 'bad', 'text': 'No VPN - your IP and location are exposed.'})

    isp = info.get('isp', '').lower()
    mobile_isps = ['mobile', 'cellular', 'airtel', 'jio', 'bsnl', 'vodafone', 'idea', 'aircel']
    big_isps = ['comcast', 'at&t', 'verizon', 'spectrum', 'cox']
    pts = 10 if any(k in isp for k in mobile_isps) else 14 if any(k in isp for k in big_isps) else 0
    score += pts
    breakdown.append({'label': 'ISP Risk', 'points': pts, 'max': 20})
    if pts > 0:
        recs.append({'type': 'bad', 'text': 'ISP ' + info.get('isp', '') + ' - use VPN on shared networks.'})
    else:
        recs.append({'type': 'good', 'text': 'ISP ' + info.get('isp', 'Unknown') + ' appears standard.'})

    high_risk = ['China', 'Russia', 'Iran', 'North Korea', 'Belarus', 'Syria']
    country = info.get('country', 'Unknown')
    pts = 15 if country in high_risk else 0
    score += pts
    breakdown.append({'label': 'Region Risk', 'points': pts, 'max': 15})
    if pts:
        recs.append({'type': 'bad', 'text': country + ' - elevated surveillance risk.'})
    else:
        recs.append({'type': 'good', 'text': country + ' - standard risk region.'})

    pts = 10 if info.get('is_hosting') else 0
    score += pts
    breakdown.append({'label': 'Network Type', 'points': pts, 'max': 20})
    if pts:
        recs.append({'type': 'bad', 'text': 'Datacenter IP - possible commercial proxy.'})

    score = max(0, min(100, score))
    level = 'Safe' if score <= 30 else 'Moderate' if score <= 60 else 'Dangerous'
    if score <= 15:
        grade = 'A+'
    elif score <= 25:
        grade = 'A'
    elif score <= 40:
        grade = 'B'
    elif score <= 55:
        grade = 'C'
    elif score <= 70:
        grade = 'D'
    else:
        grade = 'F'

    return {
        'risk': score,
        'level': level,
        'grade': grade,
        'threats': sum(1 for r in recs if r['type'] == 'bad'),
        'protections': sum(1 for r in recs if r['type'] == 'good'),
        'breakdown': breakdown,
        'recommendations': recs
    }

def build_insights(info, is_https, vpn, score):
    insights = []

    if not vpn:
        insights.append({
            'icon': '🔓',
            'severity': 'high',
            'text': 'No VPN detected - your IP address and approximate location are exposed to every website you visit.'
        })
    else:
        insights.append({
            'icon': 'shield',
            'severity': 'low',
            'text': 'VPN active - your real IP is masked and traffic is tunnelled through an encrypted connection.'
        })

    if not is_https:
        insights.append({
            'icon': '⚠️',
            'severity': 'high',
            'text': 'Lacks HTTPS - data between your device and sites is transmitted as plain text and can be intercepted.'
        })
    else:
        insights.append({
            'icon': '🔒',
            'severity': 'low',
            'text': 'HTTPS encryption is active - end-to-end encryption protects your data in transit.'
        })

    if info.get('is_mobile'):
        insights.append({
            'icon': '📱',
            'severity': 'medium',
            'text': 'Mobile data detected - generally safer than public Wi-Fi but carrier can see your traffic without VPN.'
        })
    else:
        insights.append({
            'icon': '🖥',
            'severity': 'low',
            'text': 'Residential broadband detected. If this is a public or shared network, a VPN is strongly recommended.'
        })

    if score >= 60:
        insights.append({
            'icon': '🚨',
            'severity': 'high',
            'text': 'High risk score of ' + str(score) + '/100 detected. Avoid sensitive transactions on this connection.'
        })
    elif score >= 30:
        insights.append({
            'icon': '⚠️',
            'severity': 'medium',
            'text': 'Moderate risk score of ' + str(score) + '/100. Enable a VPN and only use HTTPS sites to reduce exposure.'
        })
    else:
        insights.append({
            'icon': '✅',
            'severity': 'low',
            'text': 'Low risk score of ' + str(score) + '/100. Your connection looks clean. Keep VPN active for best privacy.'
        })

    return insights

def build_guide(info, is_https, vpn, score):
    steps = []
    step_num = 1

    if not vpn:
        steps.append({
            'step': step_num,
            'priority': 'critical',
            'title': 'Enable a VPN immediately',
            'detail': 'Your real IP address is exposed. Use Mullvad, ProtonVPN, or Windscribe. A VPN encrypts all traffic and hides your location from every site you visit.'
        })
        step_num += 1

    if not is_https:
        steps.append({
            'step': step_num,
            'priority': 'critical',
            'title': 'Only visit HTTPS websites',
            'detail': 'Look for the padlock in your browser. Install the HTTPS Everywhere extension. Never enter passwords on plain HTTP pages - your data is sent in clear text.'
        })
        step_num += 1

    steps.append({
        'step': step_num,
        'priority': 'high',
        'title': 'Turn off Wi-Fi auto-connect',
        'detail': 'Disable automatic connection to known networks. Attackers create fake hotspots matching names your device has connected to before, silently intercepting your traffic.'
    })
    step_num += 1

    steps.append({
        'step': step_num,
        'priority': 'high',
        'title': 'Enable your device firewall',
        'detail': 'Windows: Control Panel > Firewall. Mac: System Settings > Network > Firewall. A firewall blocks other users on the same network from probing your device.'
    })
    step_num += 1

    steps.append({
        'step': step_num,
        'priority': 'medium',
        'title': 'Avoid sensitive tasks on public networks',
        'detail': 'Do not log into banking, enter card details, or access critical accounts on public Wi-Fi. Use mobile data for anything sensitive - it is significantly safer.'
    })
    step_num += 1

    steps.append({
        'step': step_num,
        'priority': 'medium',
        'title': 'Enable two-factor authentication',
        'detail': 'Even if credentials are stolen on a compromised network, 2FA prevents login. Use an authenticator app like Google Authenticator or Authy over SMS where possible.'
    })
    step_num += 1

    steps.append({
        'step': step_num,
        'priority': 'low',
        'title': 'Forget the network after use',
        'detail': 'After using any public network go to Wi-Fi settings and choose Forget. This prevents your device reconnecting automatically to that network or a fake copy of it.'
    })

    return steps

def scan_ip(ip, is_https, manual_target=None):
    info = get_ip_info(ip)
    vpn = detect_vpn(info)
    result = calculate_score(info, is_https, vpn)
    result['checks'] = run_checks(info, is_https, vpn)
    result['insights'] = build_insights(info, is_https, vpn, result['risk'])
    result['secure_guide'] = build_guide(info, is_https, vpn, result['risk'])
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
        'manual_target': manual_target or ''
    }

    try:
        db = get_db()
        db.execute(
            'INSERT INTO scans (ip,city,country,isp,timezone,is_https,vpn,risk,level,grade,threats,scanned_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
            (result['detected']['ip'], result['detected']['city'],
             result['detected']['country'], result['detected']['isp'],
             result['detected']['timezone'], int(is_https), int(vpn),
             result['risk'], result['level'], result['grade'],
             result['threats'], datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
        )
        db.commit()
    except Exception as e:
        print('SQLite error: ' + str(e))

    try:
        if USE_FIREBASE and db_firebase:
            db_firebase.collection('scans').add({
                'ip': result['detected']['ip'],
                'city': result['detected']['city'],
                'country': result['detected']['country'],
                'isp': result['detected']['isp'],
                'risk': result['risk'],
                'level': result['level'],
                'grade': result['grade'],
                'scanned_at': datetime.utcnow().isoformat()
            })
    except Exception as e:
        print('Firebase error: ' + str(e))

    return result

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
    return jsonify(scan_ip(ip, is_https))

@app.route('/manual-scan', methods=['POST'])
def manual_scan():
    data = request.get_json() or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'No target provided'})

    if target.startswith('http'):
        import urllib.parse
        parsed = urllib.parse.urlparse(target)
        target = parsed.hostname or target

    is_https = (request.headers.get('X-Forwarded-Proto', 'http') == 'https'
                or request.url.startswith('https'))

    try:
        import socket
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target

    return jsonify(scan_ip(ip, is_https, manual_target=target))

@app.route('/history')
def history():
    results = []
    try:
        if USE_FIREBASE and db_firebase:
            docs = db_firebase.collection('scans').order_by(
                'scanned_at', direction='DESCENDING').limit(15).stream()
            results = [doc.to_dict() for doc in docs]
            if results:
                return jsonify(results)
    except Exception as e:
        print('Firebase history error: ' + str(e))
    try:
        db = get_db()
        rows = db.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 15').fetchall()
        results = [dict(r) for r in rows]
    except Exception as e:
        print('SQLite history error: ' + str(e))
    return jsonify(results)

@app.route('/stats')
def stats():
    try:
        db = get_db()
        total = db.execute('SELECT COUNT(*) as c FROM scans').fetchone()['c']
        dangerous = db.execute("SELECT COUNT(*) as c FROM scans WHERE level='Dangerous'").fetchone()['c']
        safe = db.execute("SELECT COUNT(*) as c FROM scans WHERE level='Safe'").fetchone()['c']
        avg = db.execute('SELECT AVG(risk) as a FROM scans').fetchone()['a'] or 0
        return jsonify({'total': total, 'dangerous': dangerous, 'safe': safe, 'avg_risk': round(avg, 1)})
    except Exception:
        return jsonify({'total': 0, 'dangerous': 0, 'safe': 0, 'avg_risk': 0})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

init_db()
