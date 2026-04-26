import os
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

def calculate_risk(data):
    score = 0
    breakdown = []
    recommendations = []

    # 1. Encryption (max 40)
    enc = data.get('encryption', 'open')
    enc_pts = {'open': 40, 'wep': 30, 'wpa': 10, 'wpa3': 0}
    enc_score = enc_pts.get(enc, 40)
    score += enc_score
    breakdown.append({'label': 'Encryption Type', 'points': enc_score, 'max': 40})
    if enc == 'open':
        recommendations.append({'type': 'bad', 'text': 'Network is completely open — anyone can intercept your data.'})
    elif enc == 'wep':
        recommendations.append({'type': 'bad', 'text': 'WEP encryption is outdated and easily cracked. Avoid this network.'})
    elif enc == 'wpa':
        recommendations.append({'type': 'bad', 'text': 'WPA is aging — prefer WPA3 networks when possible.'})
    else:
        recommendations.append({'type': 'good', 'text': 'WPA3 encryption is excellent — your connection is well encrypted.'})

    # 2. Password (max 20)
    pwd = data.get('password', 'none')
    pwd_pts = {'none': 20, 'weak': 15, 'strong': 0}
    pwd_score = pwd_pts.get(pwd, 20)
    score += pwd_score
    breakdown.append({'label': 'Password Strength', 'points': pwd_score, 'max': 20})
    if pwd == 'none':
        recommendations.append({'type': 'bad', 'text': 'No password required — this is a major security risk.'})
    elif pwd == 'weak':
        recommendations.append({'type': 'bad', 'text': 'Weak password can be brute-forced. Look for better-secured networks.'})

    # 3. HTTPS (max 15)
    https = data.get('https', False)
    https_score = 0 if https else 15
    score += https_score
    breakdown.append({'label': 'HTTPS Usage', 'points': https_score, 'max': 15})
    if not https:
        recommendations.append({'type': 'bad', 'text': 'No HTTPS — your browsing data is transmitted in plain text.'})
    else:
        recommendations.append({'type': 'good', 'text': 'HTTPS is active — your web traffic is encrypted end-to-end.'})

    # 4. Signal strength (max 10)
    signal = data.get('signal', 'weak')
    sig_pts = {'very_strong': 10, 'strong': 6, 'moderate': 3, 'weak': 0}
    sig_score = sig_pts.get(signal, 0)
    score += sig_score
    breakdown.append({'label': 'Signal Strength', 'points': sig_score, 'max': 10})
    if signal == 'very_strong':
        recommendations.append({'type': 'bad', 'text': 'Very strong signal may indicate a rogue hotspot mimicking a real network.'})

    # 5. Known network (max 15)
    known = data.get('known', False)
    known_score = 0 if known else 15
    score += known_score
    breakdown.append({'label': 'Network Trust', 'points': known_score, 'max': 15})
    if not known:
        recommendations.append({'type': 'bad', 'text': 'Unknown network — verify it\'s legitimate before connecting.'})
    else:
        recommendations.append({'type': 'good', 'text': 'You recognize this network — lower risk of rogue access points.'})

    # 6. Location risk (max 10)
    location = data.get('location', 'airport')
    loc_pts = {'airport': 10, 'cafe': 8, 'hotel': 6, 'home': 0}
    loc_score = loc_pts.get(location, 8)
    score += loc_score
    breakdown.append({'label': 'Location Risk', 'points': loc_score, 'max': 10})
    if location in ['airport', 'cafe']:
        recommendations.append({'type': 'bad', 'text': f'{location.title()} networks are high-traffic targets for attackers.'})

    # 7. VPN (reduces score by 15)
    vpn = data.get('vpn', False)
    if vpn:
        score = max(0, score - 15)
        recommendations.append({'type': 'good', 'text': 'VPN is active — your traffic is tunneled and encrypted.'})
    else:
        recommendations.append({'type': 'bad', 'text': 'No VPN detected — consider using one on public networks.'})

    # 8. Firewall (reduces score by 10)
    firewall = data.get('firewall', False)
    if firewall:
        score = max(0, score - 10)
        recommendations.append({'type': 'good', 'text': 'Firewall is enabled — helps block unauthorized access to your device.'})

    # 9. Crowded network (adds 5)
    crowded = data.get('crowded', False)
    if crowded:
        score = min(100, score + 5)
        recommendations.append({'type': 'bad', 'text': 'Many users on this network increases risk of traffic sniffing.'})

    score = max(0, min(100, score))

    # Risk level
    if score <= 30:
        level = 'Safe'
    elif score <= 60:
        level = 'Moderate'
    else:
        level = 'Dangerous'

    # Grade
    if score <= 15:
        grade = 'A+'
    elif score <= 30:
        grade = 'B'
    elif score <= 50:
        grade = 'C'
    elif score <= 70:
        grade = 'D'
    else:
        grade = 'F'

    threats = sum(1 for r in recommendations if r['type'] == 'bad')
    protections = sum(1 for r in recommendations if r['type'] == 'good')

    return {
        'risk': score,
        'level': level,
        'grade': grade,
        'threats': threats,
        'protections': protections,
        'breakdown': breakdown,
        'recommendations': recommendations
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/score', methods=['POST'])
def score():
    data = request.json
    result = calculate_risk(data)
    return jsonify(result)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
