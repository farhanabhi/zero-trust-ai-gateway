"""
security.py
Zero-Trust AI Gateway - Threat Detection (OWASP LLM01) & DLP Redaction Engine (OWASP LLM06)
Designed for high-throughput, low-memory cloud environments (Render 512MB Free Tier).
"""

import re
import base64
from dataclasses import dataclass, field
from typing import List, Dict, Tuple


@dataclass
class SecurityAssessment:
    original_prompt: str
    sanitized_prompt: str
    threat_score: float
    is_blocked: bool
    action_taken: str  # "ALLOWED", "SANITIZED", or "BLOCKED"
    triggered_rules: List[str] = field(default_factory=list)
    redacted_entities: Dict[str, int] = field(default_factory=dict)


class PromptFirewall:
    """
    Inspects prompts for adversarial injection attempts and redacts sensitive PII.
    """

    # Threat score threshold at or above which a request is immediately blocked
    BLOCK_THRESHOLD: float = 0.60

    def __init__(self) -> None:
        # 1. OWASP LLM01: Weighted Adversarial Prompt Injection Signatures
        self.injection_signatures: List[Tuple[str, re.Pattern, float]] = [
            (
                "INSTRUCTION_OVERRIDE",
                re.compile(
                    r"\b(ignore|disregard|forget|bypass|override)\b.{0,30}\b(previous|prior|above|all|system|initial)\b.{0,30}\b(instructions?|rules?|prompts?|directives?|guidelines?)\b",
                    re.IGNORECASE | re.DOTALL,
                ),
                0.85,
            ),
            (
                "SYSTEM_PROMPT_EXFILTRATION",
                re.compile(
                    r"\b(reveal|show|print|output|repeat|display|dump)\b.{0,30}\b(system\s+prompt|hidden\s+instructions?|initial\s+prompt|developer\s+message|exact\s+words\s+above)\b",
                    re.IGNORECASE | re.DOTALL,
                ),
                0.90,
            ),
            (
                "JAILBREAK_PERSONA",
                re.compile(
                    r"\b(you\s+are\s+now\s+DAN|do\s+anything\s+now|developer\s+mode\s+enabled|act\s+as\s+an?\s+unrestricted|jailbreak|evil\s+confidant|godmode)\b",
                    re.IGNORECASE,
                ),
                0.95,
            ),
            (
                "PRIVILEGE_ESCALATION_DELIMITER",
                re.compile(
                    r"(###\s*(system|instruction|override)|\[system\s*override\]|<\|im_start\|>system|sudo\s+mode|admin\s+override)",
                    re.IGNORECASE,
                ),
                0.80,
            ),
            (
                "ROLE_HIJACKING",
                re.compile(
                    r"\b(from\s+now\s+on\s+you\s+will\s+not\s+refuse|pretend\s+you\s+have\s+no\s+ethical|bypass\s+safety\s+filters|disable\s+content\s+policy)\b",
                    re.IGNORECASE,
                ),
                0.85,
            ),
            (
                "SQL_OR_CODE_INJECTION_PROBE",
                re.compile(
                    r"(\bUNION\s+SELECT\b|\bDROP\s+TABLE\b|;\s*--|\bOR\s+1\s*=\s*1\b|__import__\s*\(\s*['\"]os['\"]\s*\))",
                    re.IGNORECASE,
                ),
                0.75,
            ),
        ]

        # 2. OWASP LLM06: Data Loss Prevention (DLP) PII Entity Patterns
        self.pii_patterns: List[Tuple[str, re.Pattern, str]] = [
            (
                "EMAIL_ADDRESS",
                re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
                "[REDACTED_EMAIL]",
            ),
            (
                "CREDIT_CARD",
                re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
                "[REDACTED_CREDIT_CARD]",
            ),
            (
                "PHONE_NUMBER",
                re.compile(
                    r"(?:\+?\d{1,3}[-\s.]?)?\(?\d{3,4}\)?[-\s.]?\d{3}[-\s.]?\d{4}\b"
                ),
                "[REDACTED_PHONE]",
            ),
            (
                "API_KEY_SECRET",
                re.compile(
                    r"\b(sk-[a-zA-Z0-9]{20,}|gsk_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b"
                ),
                "[REDACTED_API_KEY]",
            ),
            (
                "GOVT_ID_PAN_SSN",
                re.compile(
                    r"\b([A-Z]{5}[0-9]{4}[A-Z]{1}|\d{3}-\d{2}-\d{4})\b"
                ),
                "[REDACTED_GOVT_ID]",
            ),
        ]

    def _check_obfuscation_heuristics(self, text: str) -> Tuple[float, List[str]]:
        """
        Detects Base64 encoded payloads or abnormal control-character density
        commonly used to bypass naive keyword filters.
        """
        score = 0.0
        reasons: List[str] = []

        # Heuristic A: Detect suspicious Base64 blobs longer than 32 chars
        b64_candidates = re.findall(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b", text)
        for candidate in b64_candidates:
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                if any(kw in decoded.lower() for kw in ["ignore", "system", "override", "password", "prompt"]):
                    score += 0.85
                    reasons.append("BASE64_OBFUSCATED_INJECTION")
                    break
            except Exception:
                pass

        # Heuristic B: High density of special/delimiter characters
        if len(text) > 25:
            special_chars = sum(1 for c in text if c in "{}[]<>|\\^~`#$*")
            if (special_chars / len(text)) > 0.28:
                score += 0.35
                reasons.append("ABNORMAL_DELIMITER_DENSITY")

        return score, reasons

    def detect_threat(self, prompt: str) -> Tuple[float, List[str]]:
        """
        Calculates cumulative threat score (0.0 to 1.0) and lists triggered security rules.
        """
        total_score = 0.0
        triggered_rules: List[str] = []

        for rule_name, pattern, weight in self.injection_signatures:
            if pattern.search(prompt):
                total_score += weight
                triggered_rules.append(rule_name)

        heuristic_score, heuristic_rules = self._check_obfuscation_heuristics(prompt)
        total_score += heuristic_score
        triggered_rules.extend(heuristic_rules)

        normalized_score = round(min(total_score, 1.0), 2)
        return normalized_score, triggered_rules

    def redact_pii(self, prompt: str) -> Tuple[str, Dict[str, int]]:
        """
        Scans and masks sensitive PII tokens before the prompt leaves the gateway.
        """
        sanitized = prompt
        redacted_counts: Dict[str, int] = {}

        for entity_type, pattern, mask in self.pii_patterns:
            matches = pattern.findall(sanitized)
            if matches:
                redacted_counts[entity_type] = len(matches)
                sanitized = pattern.sub(mask, sanitized)

        return sanitized, redacted_counts

    def inspect(self, prompt: str) -> SecurityAssessment:
        """
        Executes the full Zero-Trust inspection pipeline on an incoming prompt.
        """
        threat_score, triggered_rules = self.detect_threat(prompt)

        if threat_score >= self.BLOCK_THRESHOLD:
            return SecurityAssessment(
                original_prompt=prompt,
                sanitized_prompt="[BLOCKED_BY_ZERO_TRUST_FIREWALL]",
                threat_score=threat_score,
                is_blocked=True,
                action_taken="BLOCKED",
                triggered_rules=triggered_rules,
                redacted_entities={},
            )

        sanitized_prompt, redacted_entities = self.redact_pii(prompt)
        action_taken = "SANITIZED" if redacted_entities else "ALLOWED"

        return SecurityAssessment(
            original_prompt=prompt,
            sanitized_prompt=sanitized_prompt,
            threat_score=threat_score,
            is_blocked=False,
            action_taken=action_taken,
            triggered_rules=triggered_rules,
            redacted_entities=redacted_entities,
        )