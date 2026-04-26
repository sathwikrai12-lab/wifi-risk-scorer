import os
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

def get_ip_info(ip):
    try:
        clean_ip = ip.split(',')[0].strip()
        if clean_ip in ('127.0.0.1', '::1', 'localhost'):
            r = requests.get('https://ipapi.co/json/', timeout=5)
        else:
            r = requests.get(f'https://ipapi.co/{clean_ip}/json/', timeout=5)
        return r.json()
    except Exception:
        return {}

def check_vpn(ip_info):
    org = ip_info.get('org', '').lower()
    vpn_keywords = ['vpn', 'proxy', 'hosting', 'digitalocean', 'linode',
                    'amazon', 'google cloud', 'microsoft azure', 'cloudflare',
                    'mullvad', 'nordvpn', 'expressvpn', 'private internet']
    return any(kw in org for kw in vpn_keywords)

def score_connection(ip_info, is_https, vpn_detected):
    score = 0
    breakdown = []
    recommendations = []

    # 1. HTTPS (max 25)
    if not is_https:
        score += 25
        breakdown.append({'label': 'Connection security', 'points': 25, 'max': 25})
        recommendations.append({'type': 'bad', 'text': 'Not using HTTPS — your traffic is unencrypted.'})
    else:
        breakdown.append({'label': 'Connection security', 'points': 0, 'max': 25})
        recommendations.append({'type': 'good', 'text': 'HTTPS active — your connection is encrypted.'})

    # 2. VPN (max 20)
    if vpn_detected:
        breakdown.append({'label': 'VPN / Proxy', 'points': 0, 'max': 20})
        recommendations.append({'type': 'good', 'text': 'VPN or proxy detected — your real IP is hidden.'})
    else:
        score += 20
        breakdown.append({'label': 'VPN / Proxy', 'points': 20, 'max': 20})
        recommendations.append({'type': 'bad', 'text': 'No VPN detected — your real IP and location are visible.'})

    # 3. ISP risk (max 20)
    org = ip_info.get('org', '').lower()
    isp_risk = 0
    risky_isps = ['airtel', 'jio', 'bsnl', 'vodafone', 'comcast', 'at&t', 'public']
    if any(k in org for k in risky_isps):
        isp_risk = 10
        recommendations.append({'type': 'bad', 'text': f'ISP ({ip_info.get("org","Unknown")}) is a large public carrier — higher exposure on shared networks.'})
    breakdown.append({'label': 'ISP risk', 'points': isp_risk, 'max': 20})
    score += isp_risk

    # 4. Country risk (max 15)
    country = ip_info.get('country_name', 'Unknown')
    high_risk = ['China', 'Russia', 'Iran', 'North Korea']
    if country in high_risk:
        score += 15
        breakdown.append({'label': 'Region risk', 'points': 15, 'max': 15})
        recommendations.append({'type': 'bad', 'text': f'Connecting from {country} — higher risk of surveillance.'})
    else:
        breakdown.append({'label': 'Region risk', 'points': 0, 'max': 15})
        recommendations.append({'type': 'good', 'text': f'Region ({country}) has standard risk levels.'})

    # 5. Connection type (max 20)
    if 'mobile' in org or 'cellular' in org:
        score += 5
        breakdown.append({'label': 'Connection type', 'points': 5, 'max': 20})
        recommendations.append({'type': 'bad', 'text': 'Mobile data — safer than public Wi-Fi but still exposed.'})
    else:
        breakdown.append({'label': 'Connection type', 'points': 0, 'max': 20})

    score = max(0, min(100, score))
    level = 'Safe' if score <= 30 else 'Moderate' if score <= 60 else 'Dangerous'
    grade = 'A+' if score <= 15 else 'B' if score <= 30 else 'C' if score <= 50 else 'D' if score <= 70 else 'F'

    return {
        'risk': score, 'level': level, 'grade': grade,
        'threats': sum(1 for r in recommendations if r['type'] == 'bad'),
        'protections': sum(1 for r in recommendations if r['type'] == 'good'),
        'breakdown': breakdown, 'recommendations': recommendations
    }

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

    ip_info = get_ip_info(ip)
    vpn_detected = check_vpn(ip_info)
    result = score_connection(ip_info, is_https, vpn_detected)

    result['detected'] = {
        'ip': ip.split(',')[0].strip(),
        'isp': ip_info.get('org', 'Unknown'),
        'city': ip_info.get('city', 'Unknown'),
        'country': ip_info.get('country_name', 'Unknown'),
        'is_https': is_https,
        'vpn': vpn_detected,
        'timezone': ip_info.get('timezone', 'Unknown'),
    }
    return jsonify(result)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
