# Cartier — Explainable Web Attack Detection

Cartier is a lightweight WAF-style detector that identifies SQLi, XSS, SSRF, and RCE in HTTP requests and explains **why** it flagged them with evidence. It ships with a clean UI and both Python and Java backends so you can demo fast.

## What You Get
- Detection engine for SQLi, XSS, SSRF, RCE
- Explainable evidence per finding
- Live UI dashboard
- Python backend (Flask) and Java backend (Spark)

## Quick Demo (Fastest)
1. Run **either** backend below.
2. Open the UI in your browser.
3. Click the sample buttons (SQLi/XSS/SSRF/RCE) to show detections + evidence.

## Python Backend (Flask)
```bash
cd python
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open `http://localhost:8000`

## Java Backend (Spark)
```bash
cd java
mvn package
java -jar target/cartier-waf-1.0.0.jar
```
Open `http://localhost:8080`

## API
`POST /api/analyze`
```json
{
  "method": "POST",
  "url": "https://shop.example.com/fetch",
  "headers": "Content-Type: application/json",
  "body": "{\"url\":\"http://169.254.169.254/latest/meta-data/iam\"}"
}
```
Response includes `summary` + `findings` + `evidence`.

## Docker (Optional Hosting)
Python:
```bash
cd python
docker build -t cartier-python .
docker run -p 8000:8000 cartier-python
```

Java:
```bash
cd java
docker build -t cartier-java .
docker run -p 8080:8080 cartier-java
```

## Live Demo Script (90 seconds)
1. Show clean request → “No attacks detected”.
2. Click SQLi sample → show evidence (UNION SELECT, comments, tautology).
3. Click XSS sample → show `<script>` and event handler evidence.
4. Click SSRF sample → show internal metadata host evidence.
5. Click RCE sample → show shell chaining + suspicious binary.

## Repo Structure
- `python/` Flask backend + UI
- `java/` Spark backend + UI

## Next Steps (if time)
- Add scoring heatmap
- Export JSON logs
- Add more attack signatures
