"""
Sentinel360 - AI PII Detection Service (Claude API)
"""
from __future__ import annotations
import os, re, json, httpx, asyncio
from typing import List, Tuple, Optional
from pathlib import Path
from datetime import datetime

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = "claude-sonnet-4-20250514"
MAX_SNIPPET_CHARS = 3000
USE_AI = bool(ANTHROPIC_API_KEY)

TEXT_EXTENSIONS = {
    ".txt", ".log", ".conf", ".ini", ".py", ".js", ".ts", ".json",
    ".sql", ".env", ".xml", ".yaml", ".yml", ".csv", ".md", ".sh",
    ".rb", ".php", ".java", ".go", ".rs", ".toml", ".cfg",
}

QUICK_PATTERNS: dict[str, str] = {
    "CPF": r"\d{3}\.?\d{3}\.?\d{3}-?\d{2}",
    "CNPJ": r"\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}",
    "Email": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "Chave Privada": r"-----BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY-----",
    "Token/Secret": r"(?i)(password|secret|token|api_?key|passwd|pwd)\s*[=:]\s*\S+",
    "Cartao": r"(?:\d{4}[\s\-]?){3}\d{4}",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "JWT": r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
}

RISK_MAP: dict[str, str] = {
    "CPF": "critical", "CNPJ": "high", "Cartao": "critical",
    "Chave Privada": "critical", "AWS Key": "critical",
    "JWT": "high", "Token/Secret": "high", "Email": "medium",
}

SYSTEM_PROMPT = """Voce e um analisador de seguranca especializado em deteccao de PII.
Analise o trecho de arquivo e identifique APENAS dados realmente sensiveis.
Responda SOMENTE em JSON, sem texto adicional.
Formato: {"findings": [{"type": "...", "confidence": 0.95, "risk_level": "critical|high|medium|low", "detected_by": "claude_ai"}]}
Se nao encontrar nada, retorne {"findings": []}"""


def detect_with_regex(content: str) -> List[dict]:
    findings = []
    for label, pattern in QUICK_PATTERNS.items():
        if re.search(pattern, content):
            findings.append({"type": label, "confidence": 1.0, "snippet": None, "detected_by": "regex"})
    return findings


async def detect_with_claude(content: str, filename: str) -> List[dict]:
    if not USE_AI:
        return []
    snippet = content[:MAX_SNIPPET_CHARS]
    prompt = f"Arquivo: {filename}

Conteudo:
```
{snippet}
```"
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": CLAUDE_MODEL, "max_tokens": 800, "system": SYSTEM_PROMPT, "messages": [{"role": "user", "content": prompt}]},
            )
            resp.raise_for_status()
            raw = resp.json()["content"][0]["text"].strip()
            return json.loads(raw).get("findings", [])
        except Exception as e:
            print(f"[AI] Erro: {e}")
            return []


async def analyze_file(file_path: str) -> Tuple[List[dict], str]:
    ext = Path(file_path).suffix.lower()
    if ext not in TEXT_EXTENSIONS:
        return [], "none"
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(MAX_SNIPPET_CHARS * 2)
    except Exception:
        return [], "none"
    if not content.strip():
        return [], "none"
    regex_findings = detect_with_regex(content)
    ai_findings: List[dict] = []
    sensitive_names = {"env", "secret", "config", "credential", "password", "key", "token"}
    name_lower = Path(file_path).stem.lower()
    is_suspicious = bool(regex_findings) or any(s in name_lower for s in sensitive_names)
    if USE_AI and is_suspicious:
        ai_findings = await detect_with_claude(content, Path(file_path).name)
    all_types = {f["type"] for f in regex_findings}
    merged = list(regex_findings)
    for ai_f in ai_findings:
        if ai_f["type"] not in all_types:
            merged.append(ai_f)
    risk_level = _compute_risk_level(merged)
    return merged, risk_level


def _compute_risk_level(findings: List[dict]) -> str:
    if not findings:
        return "none"
    priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    highest = "none"
    for f in findings:
        rl = f.get("risk_level") or RISK_MAP.get(f["type"], "medium")
        if priority.get(rl, 0) > priority.get(highest, 0):
            highest = rl
    return highest


async def analyze_files_batch(file_paths: List[str], concurrency: int = 5) -> List[dict]:
    sem = asyncio.Semaphore(concurrency)
    async def _safe_analyze(path: str) -> Optional[dict]:
        async with sem:
            try:
                stats = os.stat(path)
                now = datetime.utcnow().timestamp()
                risks, rl = await analyze_file(path)
                is_inactive = (now - stats.st_atime) > (180 * 86400)
                if not risks and not is_inactive:
                    return None
                return {
                    "name": os.path.basename(path), "path": path,
                    "extension": os.path.splitext(path)[1].lower(),
                    "size_mb": round(stats.st_size / 1_048_576, 3),
                    "last_accessed": datetime.utcfromtimestamp(stats.st_atime).isoformat(),
                    "last_modified": datetime.utcfromtimestamp(stats.st_mtime).isoformat(),
                    "is_inactive": is_inactive, "risk_level": rl, "risks": risks,
                }
            except Exception:
                return None
    import os as _os
    tasks = [_safe_analyze(p) for p in file_paths]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]
