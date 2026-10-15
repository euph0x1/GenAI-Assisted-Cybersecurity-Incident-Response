"""Provider-agnostic LLM client with disk cache, rate limiting and retry.

  from src.llm import generate
  text = generate("prompt", system="...", json_mode=True)

Config (env vars or a .env file in the project root):
  LLM_PROVIDER   gemini (default) | ollama
  GEMINI_API_KEY your Google AI Studio key (never commit it)
  GEMINI_MODEL   default gemini-2.5-flash-lite  -> use whichever model AI Studio shows as free
  LLM_RPM        max requests/minute, default 8 (stay under your free-tier limit)
  OLLAMA_MODEL   default llama3.1:8b   OLLAMA_URL default http://localhost:11434

Every response is cached in cache/llm_cache.sqlite keyed by (provider, model, prompt, ...),
so re-running an experiment costs no quota and a crash loses no finished work.
"""
import hashlib, json, os, random, sqlite3, time, urllib.request

try:
    from dotenv import load_dotenv; load_dotenv()
except ImportError:
    pass

CACHE_PATH = os.environ.get("LLM_CACHE", "cache/llm_cache.sqlite")
MAX_ATTEMPTS = 6
_last_call = 0.0

def _cfg():
    p = os.environ.get("LLM_PROVIDER", "gemini").lower()
    model = (os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite") if p == "gemini"
             else os.environ.get("OLLAMA_MODEL", "llama3.1:8b"))
    return p, model

def _db():
    os.makedirs(os.path.dirname(CACHE_PATH) or ".", exist_ok=True)
    con = sqlite3.connect(CACHE_PATH)
    con.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, response TEXT)")
    return con

def _key(provider, model, system, prompt, json_mode, temperature):
    raw = json.dumps([provider, model, system, prompt, json_mode, temperature])
    return hashlib.sha256(raw.encode()).hexdigest()

def _rate_limit():
    global _last_call
    gap = 60.0 / max(float(os.environ.get("LLM_RPM", "8")), 0.1)
    wait = _last_call + gap - time.time()
    if wait > 0: time.sleep(wait)
    _last_call = time.time()

def _call_gemini(model, system, prompt, json_mode, temperature):
    from google import genai
    from google.genai import types
    key = os.environ.get("GEMINI_API_KEY")
    if not key: raise RuntimeError("GEMINI_API_KEY is not set (see .env.example)")
    client = genai.Client(api_key=key)
    cfg = types.GenerateContentConfig(
        system_instruction=system or None, temperature=temperature,
        response_mime_type="application/json" if json_mode else None)
    resp = client.models.generate_content(model=model, contents=prompt, config=cfg)
    return resp.text or ""

def _call_ollama(model, system, prompt, json_mode, temperature):
    url = os.environ.get("OLLAMA_URL", "http://localhost:11434") + "/api/generate"
    body = {"model": model, "prompt": prompt, "system": system or "", "stream": False,
            "options": {"temperature": temperature}}
    if json_mode: body["format"] = "json"
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())["response"]

def _call_provider(provider, model, system, prompt, json_mode, temperature):
    fn = {"gemini": _call_gemini, "ollama": _call_ollama}.get(provider)
    if fn is None: raise ValueError(f"unknown LLM_PROVIDER: {provider}")
    return fn(model, system, prompt, json_mode, temperature)

def generate(prompt, system=None, json_mode=False, temperature=0.0, use_cache=True):
    provider, model = _cfg()
    key = _key(provider, model, system, prompt, json_mode, temperature)
    con = _db()
    try:
        if use_cache:
            row = con.execute("SELECT response FROM cache WHERE key=?", (key,)).fetchone()
            if row: return row[0]
        for attempt in range(MAX_ATTEMPTS):
            _rate_limit()
            try:
                out = _call_provider(provider, model, system, prompt, json_mode, temperature)
                break
            except Exception as e:
                msg = str(e)
                if "API_KEY" in msg or "not set" in msg or "unknown LLM_PROVIDER" in msg: raise
                if attempt == MAX_ATTEMPTS - 1: raise
                quota = "429" in msg or "RESOURCE_EXHAUSTED" in msg
                delay = min((15 if quota else 2) * 2 ** attempt, 120) + random.random()
                print(f"[llm] {type(e).__name__}: retry {attempt+1}/{MAX_ATTEMPTS-1} in {delay:.0f}s")
                time.sleep(delay)
        if out:  # never cache empty responses
            con.execute("INSERT OR REPLACE INTO cache VALUES (?,?)", (key, out)); con.commit()
        return out
    finally:
        con.close()
