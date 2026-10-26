import os
import hashlib
import base64
import requests
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from google import genai
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paste your keys here for local testing, or set them as Environment Variables
VT_API_KEY = os.getenv("VT_API_KEY", "PASTE_YOUR_VIRUSTOTAL_API_KEY_HERE")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "PASTE_YOUR_GEMINI_API_KEY_HERE")

def get_ai_summary(scan_type: str, target_name: str, stats: dict) -> str:
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        prompt = (
            f"You are a cybersecurity assistant. A user scanned a {scan_type} named '{target_name}'. "
            f"Out of multiple antivirus engines, here are the results: {stats}. "
            f"In 3 short, beginner-friendly bullet points, explain whether this is safe, "
            f"what the risk level is, and what the user should do next."
        )
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        return response.text
    except Exception as e:
        return f"AI Summary unavailable (Check your Gemini API key). Raw stats: {stats}"

@app.get("/", response_class=HTMLResponse)
async def serve_home():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/scan-url")
async def scan_url(url: str = Form(...)):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    else:
        # Submit URL for scanning if not already in database
        post_res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        if post_res.status_code != 200:
            return {"error": "Could not scan URL. Check your VirusTotal API Key."}
        stats = {"malicious": 0, "suspicious": 0, "harmless": 1, "note": "URL queued for fresh analysis"}

    ai_advice = get_ai_summary("URL", url, stats)
    return {"target": url, "stats": stats, "ai_explanation": ai_advice}

@app.post("/scan-file")
async def scan_file(file: UploadFile = File(...)):
    content = await file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)

    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    else:
        stats = {"malicious": 0, "suspicious": 0, "undetected": 1, "note": "File hash not found in known malware database (Likely a clean or newly created personal file)."}

    ai_advice = get_ai_summary("File", file.filename, stats)
    return {"target": file.filename, "sha256": file_hash, "stats": stats, "ai_explanation": ai_advice}