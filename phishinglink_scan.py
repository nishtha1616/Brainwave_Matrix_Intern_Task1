import re
from urllib.parse import urlparse

def is_ip_address(url):
    return bool(re.match(r"https?://\d+\.\d+\.\d+\.\d+", url))

def has_at_symbol(url):
    return '@' in url

def is_long_url(url, threshold=75):
    return len(url) > threshold

def has_suspicious_words(url):
    suspicious_words = ['login', 'verify', 'update', 'free', 'bonus', 'banking']
    return any(word in url.lower() for word in suspicious_words)

def check_url(url):
    print(f"\n🔎 Checking URL: {url}")
    score = 0

    if is_ip_address(url):
        print("⚠️ URL contains IP address.")
        score += 1

    if has_at_symbol(url):
        print("⚠️ URL contains '@' symbol.")
        score += 1

    if is_long_url(url):
        print("⚠️ URL is too long.")
        score += 1

    if has_suspicious_words(url):
        print("⚠️ Suspicious words found in URL.")
        score += 1

    if score >= 2:
        return "🔴 Potential Phishing Link!"
    elif score == 1:
        return "🟠 Slightly Suspicious"
    else:
        return "🟢 URL looks safe"

# Test the scanner
urls = [
    "http://192.168.1.1/login",
    "https://secure-update.bank.com.free-money.ru@malicious.com",
    "https://google.com",
    "https://verylongurl1234567890.com/free/gift/bonus.html"
]

for url in urls:
    result = check_url(url)
    print(f"✅ Result: {result}")
