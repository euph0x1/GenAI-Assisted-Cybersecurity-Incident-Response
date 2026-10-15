"""Smoke test: python -m src.llm_check"""
import os
from src.llm import generate, _cfg
p, m = _cfg()
print(f"provider={p} model={m} key_set={bool(os.environ.get('GEMINI_API_KEY'))}")
print(generate('Reply with exactly the JSON {"ok": true}', json_mode=True, use_cache=False))
