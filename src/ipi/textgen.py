"""Plain text-completion helper for *auxiliary* LLMs (envelope extractor, policy generator, attacker).
Separate from the agent backbone so each can use a different (usually cheaper) model.

Cached on disk: identical (provider, model, system, prompt, salt) never hits the API twice.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
from pathlib import Path

_DB_LOCK = threading.Lock()
_DB: sqlite3.Connection | None = None


def _db(path: str = "results/cache/textgen.sqlite") -> sqlite3.Connection:
    global _DB
    if _DB is None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        _DB = sqlite3.connect(path, check_same_thread=False)
        _DB.execute("CREATE TABLE IF NOT EXISTS c (k TEXT PRIMARY KEY, v TEXT)")
    return _DB


def complete(prompt: str, *, provider: str, model: str, system: str = "", temperature: float = 0.0,
             max_tokens: int = 2048, salt: str = "", use_cache: bool = True) -> str:
    key = hashlib.sha256(json.dumps([provider, model, system, prompt, temperature, salt]).encode()).hexdigest()
    if use_cache:
        with _DB_LOCK:
            row = _db().execute("SELECT v FROM c WHERE k=?", (key,)).fetchone()
        if row:
            return row[0]

    if provider == "anthropic":
        import anthropic

        from ipi.llm import accepts_sampling_params, log_usage
        kwargs = {"system": system} if system else {}
        if accepts_sampling_params(model):
            kwargs["temperature"] = temperature
        else:
            max_tokens = max(max_tokens, 16000)  # adaptive thinking is on by default and shares this budget
        r = anthropic.Anthropic().messages.create(
            model=model, max_tokens=max_tokens, messages=[{"role": "user", "content": prompt}], **kwargs)
        log_usage(model, r.usage, "aux", r.stop_reason)
        text = "".join(b.text for b in r.content if b.type == "text")
        if r.stop_reason == "refusal":
            use_cache = False  # don't pin a refusal into the cache; a rerun gets a fresh sample
    elif provider in ("openai", "openai-compat"):
        import openai
        from ipi.llm import compat_client
        client = openai.OpenAI(max_retries=12) if provider == "openai" else compat_client()
        msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
        # reasoning models (Gemini 3.x, o-series) spend part of max_tokens on hidden thinking
        r = client.chat.completions.create(model=model, messages=msgs, temperature=temperature,
                                           max_tokens=max(max_tokens, 16000) if provider == "openai-compat" else max_tokens)
        if r.usage:
            from types import SimpleNamespace
            from ipi.llm import log_usage
            log_usage(model, SimpleNamespace(input_tokens=r.usage.prompt_tokens, output_tokens=r.usage.completion_tokens),
                      "aux", r.choices[0].finish_reason)
        text = r.choices[0].message.content or ""
    else:
        raise ValueError(f"textgen: unsupported provider {provider!r}")

    if use_cache:
        with _DB_LOCK:
            _db().execute("INSERT OR REPLACE INTO c VALUES (?,?)", (key, text))
            _db().commit()
    return text


def extract_json(text: str):
    """Pull the first JSON object/array out of a model response (handles ```json fences)."""
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1)
    start = min([i for i in (text.find("{"), text.find("[")) if i != -1], default=-1)
    if start == -1:
        raise ValueError("no JSON found in model output")
    return json.JSONDecoder().raw_decode(text[start:])[0]
