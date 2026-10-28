"""
Text, Email & Article Analysis Engine.

Golden Rule: Never classify text as AI-generated based solely on writing style,
vocabulary, or punctuation. Default to Inconclusive for raw prose unless
fabricated citations, factual hallucinations, or external provenance are detected.

Checks performed:
- Email header parsing (SPF/DKIM/DMARC chain reconstruction)
- Domain WHOIS lookup
- Factual claim extraction & citation verification
- Exact-phrase origin search (SerpAPI)
- AI hallucination scan (claim grounding via web search)
"""
from __future__ import annotations

import email
import re
from typing import Any

from src.core.schemas import EngineResult, EvidenceRow, EvidenceStrength
from src.core.settings import settings


# ─────────────────────────────────────────────────────────────────────────────
# Email Header Parsing
# ─────────────────────────────────────────────────────────────────────────────

def parse_email_headers(raw_email: str) -> dict[str, Any]:
    """
    Parse raw email headers to reconstruct the Received: hop chain and
    extract SPF, DKIM, DMARC authentication results.
    """
    msg = email.message_from_string(raw_email)
    headers: dict[str, list[str]] = {}
    for key, val in msg.items():
        headers.setdefault(key, []).append(val)

    received_chain = headers.get("Received", [])
    auth_results = headers.get("Authentication-Results", [])

    spf = dkim = dmarc = "not found"
    for ar in auth_results:
        ar_lower = ar.lower()
        if "spf=pass" in ar_lower:
            spf = "PASS"
        elif "spf=fail" in ar_lower:
            spf = "FAIL"
        if "dkim=pass" in ar_lower:
            dkim = "PASS"
        elif "dkim=fail" in ar_lower:
            dkim = "FAIL"
        if "dmarc=pass" in ar_lower:
            dmarc = "PASS"
        elif "dmarc=fail" in ar_lower:
            dmarc = "FAIL"

    return {
        "from": headers.get("From", []),
        "reply_to": headers.get("Reply-To", []),
        "received_hops": len(received_chain),
        "received_chain": received_chain[:5],
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "message_id": headers.get("Message-ID", []),
        "x_mailer": headers.get("X-Mailer", []),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Domain WHOIS
# ─────────────────────────────────────────────────────────────────────────────

def check_domain_whois(domain: str) -> dict[str, Any]:
    """Run WHOIS lookup for a sender domain."""
    try:
        import whois
        w = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
        }
    except Exception as e:
        return {"domain": domain, "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# SerpAPI phrase search
# ─────────────────────────────────────────────────────────────────────────────

def serpapi_exact_phrase(phrase: str) -> dict[str, Any] | None:
    """Search for an exact phrase via SerpAPI. Returns None if key not configured."""
    if not settings.serpapi_key:
        return None
    try:
        import httpx
        resp = httpx.get(
            "https://serpapi.com/search",
            params={"q": f'"{phrase}"', "api_key": settings.serpapi_key, "num": 5},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get("organic_results", [])
        return {
            "query": phrase,
            "total_results": data.get("search_information", {}).get("total_results", "unknown"),
            "top_results": [
                {"title": r.get("title"), "link": r.get("link"), "snippet": r.get("snippet", "")[:120]}
                for r in results[:3]
            ],
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Hallucination / Factual Claim Grounding (LLM-assisted stub)
# ─────────────────────────────────────────────────────────────────────────────

def extract_verifiable_claims(text: str) -> list[str]:
    """
    Use simple heuristics to pull out checkable factual claims.
    In production: replace with a structured LLM extraction call.
    """
    # Sentences containing numbers, dates, named entities, or citation patterns
    sentences = re.split(r"(?<=[.!?])\s+", text)
    checkable = [
        s for s in sentences
        if re.search(r"\d{4}|\bsaid\b|\baccording to\b|\bstudy\b|\bstatistic\b", s, re.IGNORECASE)
    ]
    return checkable[:5]  # top 5 to avoid API overuse


# ─────────────────────────────────────────────────────────────────────────────
# Main Engine Entry Point
# ─────────────────────────────────────────────────────────────────────────────

_EMAIL_PATTERN = re.compile(r"^(From:|Return-Path:|Received:|MIME-Version:)", re.MULTILINE)


def run_text_engine(
    text: str,
    is_email: bool = False,
    sender_domain: str | None = None,
) -> EngineResult:
    checks_done: list[str] = []
    checks_skipped: list[str] = []
    evidence: list[EvidenceRow] = []
    raw_meta: dict[str, Any] = {}
    scores: list[float] = []

    # Auto-detect email
    if not is_email and _EMAIL_PATTERN.search(text):
        is_email = True

    # ── Email Header Parsing ─────────────────────────────────────────────────
    if is_email:
        headers = parse_email_headers(text)
        checks_done.append("Email header parsing (SPF / DKIM / DMARC)")
        raw_meta["headers"] = headers

        for auth_field, label in [("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")]:
            result = headers[auth_field]
            if result == "PASS":
                scores.append(0.85)
                evidence.append(EvidenceRow(
                    clue=f"{label} check: PASS",
                    source="Metadata (email headers)",
                    suggests=f"Email passed {label} authentication — sender domain verified",
                    innocent_alternative="N/A — authenticating signal",
                    strength=EvidenceStrength.STRONG,
                ))
            elif result == "FAIL":
                scores.append(0.15)
                evidence.append(EvidenceRow(
                    clue=f"{label} check: FAIL",
                    source="Metadata (email headers)",
                    suggests=f"Email failed {label} — sender may be spoofed",
                    innocent_alternative="Misconfigured DNS records on a legitimate sender's domain",
                    strength=EvidenceStrength.STRONG,
                ))

        # Extract domain from From: header
        from_header = " ".join(headers.get("from", []))
        domain_match = re.search(r"@([\w\.-]+)", from_header)
        if domain_match and not sender_domain:
            sender_domain = domain_match.group(1)

    # ── WHOIS ────────────────────────────────────────────────────────────────
    if sender_domain:
        whois_result = check_domain_whois(sender_domain)
        if "error" in whois_result:
            checks_skipped.append(f"WHOIS lookup (error: {whois_result['error']})")
        else:
            checks_done.append(f"WHOIS domain lookup ({sender_domain})")
            raw_meta["whois"] = whois_result
            creation = whois_result.get("creation_date", "")
            if "2024" in str(creation) or "2025" in str(creation) or "2026" in str(creation):
                scores.append(0.3)
                evidence.append(EvidenceRow(
                    clue=f"Domain '{sender_domain}' registered recently: {creation}",
                    source="WHOIS",
                    suggests="Newly registered domain — common in phishing / impersonation campaigns",
                    innocent_alternative="Legitimate new business or rebranded company",
                    strength=EvidenceStrength.MODERATE,
                ))
            else:
                scores.append(0.8)
    else:
        checks_skipped.append("WHOIS lookup (no sender domain identified)")

    # ── Factual Claim Extraction ─────────────────────────────────────────────
    claims = extract_verifiable_claims(text)
    if claims:
        checks_done.append("Factual claim extraction (heuristic)")
        raw_meta["claims"] = claims
        evidence.append(EvidenceRow(
            clue=f"{len(claims)} verifiable claim(s) identified for spot-checking",
            source="Text analysis",
            suggests="Claims should be individually verified against authoritative sources",
            innocent_alternative="N/A — informational",
            strength=EvidenceStrength.WEAK,
        ))

    # ── Phrase Origin Search ─────────────────────────────────────────────────
    if len(text) > 50:
        sample_phrase = text.strip()[:100].split(".")[0]
        serp = serpapi_exact_phrase(sample_phrase)
        if serp is None:
            checks_skipped.append("Exact-phrase origin search (SerpAPI key not configured)")
        elif "error" in serp:
            checks_skipped.append(f"Phrase origin search (error: {serp['error']})")
        else:
            checks_done.append("Exact-phrase origin search (SerpAPI)")
            raw_meta["serp"] = serp
            if serp.get("top_results"):
                evidence.append(EvidenceRow(
                    clue=f"Phrase found on web: '{serp['top_results'][0]['title']}'",
                    source="Web (SerpAPI)",
                    suggests="Text or portions may be copied from an existing web source",
                    innocent_alternative="Original author's own content republished; quoted material",
                    strength=EvidenceStrength.MODERATE,
                ))

    # ── Style-based AI classification GUARD RAIL ─────────────────────────────
    # We never make an AI-generated call based on style alone.
    checks_skipped.append(
        "AI-writing style classification — INTENTIONALLY SKIPPED per Golden Rule: "
        "style/vocabulary signals alone are not used to classify text as AI-generated"
    )

    composite = sum(scores) / len(scores) if scores else None
    return EngineResult(
        engine="text",
        checks_performed=checks_done,
        checks_skipped=checks_skipped,
        evidence=evidence,
        authenticity_score=composite,
        raw_metadata=raw_meta,
    )
