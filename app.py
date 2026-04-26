import os
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

def get_ip_info(ip):
    """Try multiple free IP APIs in order until one works"""
    clean_ip = ip.split(',')[0].strip()

    # If local, get public IP info instead
    is_local = clean_ip in ('127.0.0.1', '::1', 'localhost')

    apis = [
        # API 1: ip-api.com (very reliable, no key needed)
        lambda: requests.get(
            f'http://ip-api.com/json/{("" if is_local else clean_ip)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting',
            timeout=5
        ).json(),

        # API 2: ipwho.is (good backup)
        lambda: requests.get(
            f'https://ipwho.is/{("" if is_local else clean_ip)}',
            timeout=5
        ).json(),

        # API 3: ipapi.co (third fallback)
        lambda: requests.get(
            f'https://ipapi.co/{("" if is_local else clean_ip)}/json/',
            timeout=5
        ).json(),
    ]

    for api in apis:
        try:
            data = api()
            # Normalize different API response formats into one standard format
            normalized = normalize(data, clean_ip)
            if normalized.get('city') and normalized['city'] != 'Unknown':
                return normalized
        except Exception:
            continue

    return {'ip': clean_ip, 'city': 'Unknown', 'country': 'Unknown',
            'isp': 'Unknown', 'org': '', 'timezone': 'Unknown',
            'is_proxy': False, 'is_hosting': False}

def normalize(data, ip):
    """Convert any API response into a standard dict"""
    # ip-api.com format
    if 'countryCode' in data or 'regionName' in data:
        return {
            'ip': data.get('query', ip),
            'city': data.get('city', 'Unknown'),
            'region': data.get('regionName', ''),
            'country': data.get('country', 'Unknown'),
            'country_code': data.get('countryCode', ''),
            'isp': data.get('isp', data.get('org', 'Unknown')),
            'org': data.get('org', data.get('isp', '')),
            'timezone': data.get('timezone', 'Unknown'),
            'is_proxy': data.get('proxy', False),
            'is_hosting': data.get('hosting', False),
        }

    # ipwho.is format
    if 'connection' in data:
        conn = data.get('connection', {})
        return {
            'ip': data.get('ip', ip),
            'city': data.get('city', 'Unknown'),
            'region': data.get('region', ''),
            'country': data.get('country', 'Unknown'),
            'country_code': data.get('country_code', ''),
            'isp': conn.get('isp', 'Unknown'),
            'org': conn.get('org', ''),
            'timezone': data.get('timezone', {}).get('id', 'Unknown') if isinstance(data.get('timezone'), dict) else str(data.get('timezone', 'Unknown')),
            'is_proxy': data.get('security', {}).get('proxy', False),
            'is_hosting': data.get('security', {}).get('hosting', False),
        }

    # ipapi.co format
    return {
        'ip': data.get('ip', ip),
        'city': data.get('city', 'Unknown'),
        'region': data.get('region', ''),
        'country': data.get('country_name', 'Unknown'),
        'country_code': data.get('country_code', ''),
        'isp': data.get('org', 'Unknown'),
        'org': data.get('org', ''),
        'timezone': data.get('timezone', 'Unknown'),
        'is_proxy': False,
        'is_hosting': False,
    }

def check_vpn(info):
    """Detect VPN/proxy using both API flags and org name keywords"""
    if info.get('is_proxy') or info.get('is_hosting'):
        return True
    org = (info.get('org', '') + ' ' + info.get('isp', '')).lower()
    keywords = ['vpn', 'proxy', 'hosting', 'digitalocean', 'linode', 'vultr',
                'amazon', 'google cloud', 'microsoft azure', 'cloudflare',
                'mullvad', 'nordvpn', 'expressvpn', 'private internet',
                'datacenter', 'data center', 'server', 'hetzner', 'ovh']
    return any(k in org for k in keywords)

def score_connection(info, is_https, vpn_detected):
    score = 0
    breakdown = []
    recommendations = []

    # 1. HTTPS (max 25)
    if not is_https:
        score += 25
        breakdown.append({'label': 'Connection security', 'points': 25, 'max': 25})
        recommendations.append({'type': 'bad', 'text': 'Not using HTTPS — traffic between you and this site is unencrypted.'})
    else:
        breakdown.append({'label': 'Connection security', 'points': 0, 'max': 25})
        recommendations.append({'type': 'good', 'text': 'HTTPS is active — your connection to this site is encrypted.'})

    # 2. VPN (max 20)
    if vpn_detected:
        breakdown.append({'label': 'VPN / Proxy', 'points': 0, 'max': 20})
        recommendations.append({'type': 'good', 'text': 'VPN or proxy detected — your real IP and identity are masked.'})
    else:
        score += 20
        breakdown.append({'label': 'VPN / Proxy', 'points': 20, 'max': 20})
        recommendations.append({'type': 'bad', 'text': 'No VPN detected — your real IP and location are exposed to every site you visit.'})

    # 3. ISP type risk (max 20)
    isp = info.get('isp', '').lower()
    isp_score = 0
    mobile_keywords = ['mobile', 'cellular', 'airtel', 'jio', 'bsnl', 'vi ', 'vodafone', 'idea', 'aircel']
    public_keywords = ['comcast', 'at&t', 'verizon', 'spectrum', 'cox', 'public']
    if any(k in isp for k in mobile_keywords):
        isp_score = 8
        recommendations.append({'type': 'bad', 'text': f'Mobile carrier detected ({info.get("isp","")}) — mobile data is generally safer than public Wi-Fi but not private.'})
    elif any(k in isp for k in public_keywords):
        isp_score = 12
        recommendations.append({'type': 'bad', 'text': f'Public ISP ({info.get("isp","")}) — use a VPN on shared or public networks.'})
    else:
        recommendations.append({'type': 'good', 'text': f'ISP ({info.get("isp","Unknown")}) appears to be a standard carrier.'})
    score += isp_score
    breakdown.append({'label': 'ISP risk', 'points': isp_score, 'max': 20})

    # 4. Country risk (max 15)
    country = info.get('country', 'Unknown')
    high_risk = ['China', 'Russia', 'Iran', 'North Korea', 'Belarus']
    if country in high_risk:
        score += 15
        breakdown.append({'label': 'Region risk', 'points': 15, 'max': 15})
        recommendations.append({'type': 'bad', 'text': f'Connecting from {country} — higher risk of government surveillance and censorship.'})
    else:
        breakdown.append({'label': 'Region risk', 'points': 0, 'max': 15})
        recommendations.append({'type': 'good', 'text': f'Connecting from {country} — standard regional risk level.'})

    # 5. Proxy/datacenter (max 20)
    if info.get('is_hosting'):
        score += 10
        breakdown.append({'label': 'Network type', 'points': 10, 'max': 20})
        recommendations.append({'type': 'bad', 'text': 'Traffic is routed through a datacenter — could be a shared or commercial proxy.'})
    else:
        breakdown.append({'label': 'Network type', 'points': 0, 'max': 20})

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

    info = get_ip_info(ip)
    vpn_detected = check_vpn(info)
    result = score_connection(info, is_https, vpn_detected)

    result['detected'] = {
        'ip': info.get('ip', ip.split(',')[0].strip()),
        'isp': info.get('isp', 'Unknown'),
        'city': info.get('city', 'Unknown'),
        'region': info.get('region', ''),
        'country': info.get('country', 'Unknown'),
        'is_https': is_https,
        'vpn': vpn_detected,
        'timezone': info.get('timezone', 'Unknown'),
    }
    return jsonify(result)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
