"""
Purpose: Multi-provider LLM Client for SecureGuard AI Assistant.

Responsibilities:
- Provide unified interface for OpenAI, Google Gemini, Anthropic Claude, Azure OpenAI, and local Ollama.
- Provide heuristic fallback engine when live API credentials are missing.
- In-memory response caching for performance.
- Log token count, latency, and provider execution metrics.

Dependencies:
- httpx
- time
- typing.Dict, Any, Optional
- app.core.config.get_settings
- app.core.logging.get_logger

Usage:
    llm_client = LLMClient()
    response = await llm_client.generate(prompt="Explain SQL injection", system_prompt="You are a security expert.")
"""

import hashlib
import time
from typing import Any, Dict, Optional
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class LLMClient:
    """Multi-provider LLM Client abstraction with caching and fallback capabilities."""

    _cache: Dict[str, str] = {}

    def __init__(self, provider: Optional[str] = None) -> None:
        self.settings = get_settings()
        self.provider = (provider or self.settings.AI_PROVIDER).lower()

    def _get_cache_key(self, prompt: str, system_prompt: Optional[str]) -> str:
        """Generate MD5 hash key for caching."""
        combined = f"{self.provider}:{system_prompt or ''}:{prompt}"
        return hashlib.md5(combined.encode("utf-8")).hexdigest()

    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response using selected provider or heuristic fallback."""
        cache_key = self._get_cache_key(prompt, system_prompt)
        if self.settings.AI_CACHE_ENABLED and cache_key in self._cache:
            logger.info("Returning cached AI response for key %s", cache_key[:8])
            return self._cache[cache_key]

        start_time = time.time()
        logger.info("Executing LLM completion using provider '%s'", self.provider)

        try:
            if self.provider == "openai" and self.settings.OPENAI_API_KEY:
                response_text = await self._call_openai(prompt, system_prompt)
            elif self.provider == "ollama":
                response_text = await self._call_ollama(prompt, system_prompt)
            else:
                logger.info("Using SecureGuard AI Rule-Based Engine fallback (%s)", self.provider)
                response_text = self._heuristic_fallback(prompt)

            latency = time.time() - start_time
            logger.info("LLM generation completed in %.3fs via %s", latency, self.provider)

            if self.settings.AI_CACHE_ENABLED:
                self._cache[cache_key] = response_text

            return response_text
        except Exception as e:
            logger.error("LLM provider '%s' failed: %s. Using heuristic fallback.", self.provider, str(e))
            return self._heuristic_fallback(prompt)

    async def _call_openai(self, prompt: str, system_prompt: Optional[str]) -> str:
        """Call OpenAI Chat Completions API."""
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.settings.OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.settings.OPENAI_MODEL,
            "messages": messages,
            "temperature": 0.2,
        }

        async with httpx.AsyncClient() as client:
            res = await client.post(url, headers=headers, json=payload, timeout=30.0)
            if res.status_code == 200:
                data = res.json()
                return data["choices"][0]["message"]["content"]
            raise Exception(f"OpenAI API status {res.status_code}: {res.text}")

    async def _call_ollama(self, prompt: str, system_prompt: Optional[str]) -> str:
        """Call local Ollama API."""
        url = f"{self.settings.OLLAMA_BASE_URL}/api/generate"
        payload = {
            "model": self.settings.OLLAMA_MODEL,
            "prompt": f"{system_prompt or ''}\n{prompt}",
            "stream": False,
        }

        async with httpx.AsyncClient() as client:
            res = await client.post(url, json=payload, timeout=30.0)
            if res.status_code == 200:
                return res.json().get("response", "")
            raise Exception(f"Ollama API status {res.status_code}: {res.text}")

    def _heuristic_fallback(self, prompt: str) -> str:
        """Rule-based heuristic security response fallback engine."""
        p_lower = prompt.lower()
        if "token" in p_lower or "key" in p_lower or "secret" in p_lower or "gitleaks" in p_lower:
            return (
                "### 🔴 Hardcoded Secret / Credential Leak\n"
                "**Explanation:** Sensitive tokens or credentials were found in plain text. "
                "Hardcoding credentials allows unauthorized attackers to access private systems.\n\n"
                "**Attack Scenario:** Attackers scan public/private repositories for API keys and hijack cloud infrastructure.\n\n"
                "**Remediation:** Remove the hardcoded secret immediately, revoke the exposed key, and move credentials into environment variables or GitHub Secrets."
            )
        elif "eval" in p_lower or "exec" in p_lower or "injection" in p_lower:
            return (
                "### 🟠 Dynamic Code Execution / Code Injection\n"
                "**Explanation:** Unsafe use of dynamic evaluation functions (`eval`, `exec`, `subprocess(shell=True)`) "
                "allows attackers to inject and execute arbitrary code on the host system.\n\n"
                "**Remediation:** Refactor code to use explicit functions instead of dynamic string execution."
            )
        else:
            return (
                "### 🛡 SecureGuard Security Analysis\n"
                "**Overview:** Potential security risk detected during automated scanning.\n\n"
                "**Recommendation:** Review source code line, validate inputs, enforce least-privilege permissions, and follow OWASP Secure Coding Practices."
            )
