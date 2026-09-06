from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def home():
    return jsonify({
        "application": "Domain Investigation & Brand Impersonation Detection Engine",
        "status": "running"
    })

    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)