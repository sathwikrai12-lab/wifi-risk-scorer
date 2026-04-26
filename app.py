from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

def calculate_risk(data):
    score = 0

    if data['encryption'] == "open":
        score += 40
    if data['password'] == "weak":
        score += 20
    if not data['https']:
        score += 15
    if data['signal'] == "very_strong":
        score += 10
    if not data['known']:
        score += 15

    return score

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/score', methods=['POST'])
def score():
    data = request.json
    risk = calculate_risk(data)

    if risk <= 30:
        level = "Safe"
    elif risk <= 60:
        level = "Moderate"
    else:
        level = "Dangerous"

    return jsonify({"risk": risk, "level": level})
import os

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
