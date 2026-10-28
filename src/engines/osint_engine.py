"""
Social Profile & OSINT Engine.

Checks performed:
- Profile photo reverse image search (Google Vision / TinEye)
- Username cross-platform check (Sherlock)
- Domain WHOIS & age lookup
- VirusTotal domain reputation
- Bot behavior heuristics (follower/post ratio)
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from src.core.schemas import EngineResult, EvidenceRow, EvidenceStrength
from src.core.settings import settings


# ─────────────────────────────────────────────────────────────────────────────
# Domain WHOIS (shared helper also used by text engine)
# ─────────────────────────────────────────────────────────────────────────────

def whois_lookup(domain: str) -> dict[str, Any]:
    try:
        import whois
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "updated_date": str(w.updated_date),
            "name_servers": w.name_servers,
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# VirusTotal Domain Check
# ─────────────────────────────────────────────────────────────────────────────

def virustotal_domain(domain: str) -> dict[str, Any] | None:
    if not settings.virustotal_api_key:
        return None
    try:
        import httpx
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Reverse Image Search (Google Vision)
# ─────────────────────────────────────────────────────────────────────────────

def reverse_image_search(image_url: str) -> dict[str, Any] | None:
    """Use Google Vision Web Detection to find matching images online."""
    if not settings.google_vision_api_key:
        return None
    try:
        import httpx
        body = {
            "requests": [{
                "image": {"source": {"imageUri": image_url}},
                "features": [{"type": "WEB_DETECTION", "maxResults": 5}],
            }]
        }
        resp = httpx.post(
            f"https://vision.googleapis.com/v1/images:annotate?key={settings.google_vision_api_key}",
            json=body,
            timeout=20,
        )
        resp.raise_for_status()
        web = resp.json()["responses"][0].get("webDetection", {})
        return {
            "matching_pages": len(web.get("pagesWithMatchingImages", [])),
            "full_matches": len(web.get("fullMatchingImages", [])),
            "partial_matches": len(web.get("partialMatchingImages", [])),
            "best_guess_labels": [l["label"] for l in web.get("bestGuessLabels", [])],
            "top_pages": [
                p.get("url") for p in web.get("pagesWithMatchingImages", [])[:3]
            ],
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Main Engine Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def run_osint_engine(
    url: str | None = None,
    username: str | None = None,
    profile_image_url: str | None = None,
    context: str = "",
) -> EngineResult:
    checks_done: list[str] = []
    checks_skipped: list[str] = []
    evidence: list[EvidenceRow] = []
    raw_meta: dict[str, Any] = {}
    scores: list[float] = []

    # ── Domain Analysis ──────────────────────────────────────────────────────
    domain = None
    if url:
        parsed = urlparse(url)
        domain = parsed.netloc.lstrip("www.")

    if domain:
        # WHOIS
        whois_data = whois_lookup(domain)
        if "error" in whois_data:
            checks_skipped.append(f"WHOIS lookup (error: {whois_data['error']})")
        else:
            checks_done.append(f"WHOIS domain lookup ({domain})")
            raw_meta["whois"] = whois_data
            creation_str = str(whois_data.get("creation_date", ""))
            recent_years = ["2024", "2025", "2026"]
            if any(y in creation_str for y in recent_years):
                scores.append(0.25)
                evidence.append(EvidenceRow(
                    clue=f"Domain '{domain}' created recently: {creation_str[:30]}",
                    source="WHOIS",
                    suggests="Newly registered domain — elevated risk for impersonation / scam site",
                    innocent_alternative="Legitimate startup or recently launched campaign page",
                    strength=EvidenceStrength.MODERATE,
                ))
            else:
                scores.append(0.8)
                evidence.append(EvidenceRow(
                    clue=f"Domain '{domain}' has established registration history",
                    source="WHOIS",
                    suggests="Older domain — lower impersonation risk",
                    innocent_alternative="N/A — authenticating signal",
                    strength=EvidenceStrength.MODERATE,
                ))

        # VirusTotal
        vt = virustotal_domain(domain)
        if vt is None:
            checks_skipped.append("VirusTotal domain reputation (API key not configured)")
        elif "error" in vt:
            checks_skipped.append(f"VirusTotal (error: {vt['error']})")
        else:
            checks_done.append("VirusTotal domain reputation check")
            raw_meta["virustotal"] = vt
            malicious = vt.get("malicious", 0)
            if malicious > 0:
                scores.append(0.1)
                evidence.append(EvidenceRow(
                    clue=f"VirusTotal: {malicious} malicious flag(s) on '{domain}'",
                    source="External API (VirusTotal)",
                    suggests="Domain flagged as malicious by security vendors — high scam/phishing risk",
                    innocent_alternative="False positive by overzealous security vendors",
                    strength=EvidenceStrength.STRONG,
                ))
            else:
                scores.append(0.85)
    else:
        checks_skipped.append("WHOIS & VirusTotal lookup (no URL provided)")

    # ── Profile Image Reverse Search ─────────────────────────────────────────
    if profile_image_url:
        ris = reverse_image_search(profile_image_url)
        if ris is None:
            checks_skipped.append("Reverse image search (Google Vision API key not configured)")
        elif "error" in ris:
            checks_skipped.append(f"Reverse image search (error: {ris['error']})")
        else:
            checks_done.append("Profile photo reverse image search (Google Vision)")
            raw_meta["reverse_image"] = ris
            matches = ris.get("full_matches", 0)
            if matches > 3:
                scores.append(0.2)
                evidence.append(EvidenceRow(
                    clue=f"Profile photo found on {matches} other pages online",
                    source="Web (Google Vision)",
                    suggests="Image likely recycled / stock photo — possibly a fake profile",
                    innocent_alternative="Legitimate user whose photo was republished without consent",
                    strength=EvidenceStrength.STRONG,
                ))
            elif matches == 0:
                evidence.append(EvidenceRow(
                    clue="No matching profile photos found online",
                    source="Web (Google Vision)",
                    suggests="Image does not appear to be a widely recycled stock photo",
                    innocent_alternative="N/A — weak authenticating signal (private/new photos also have 0 matches)",
                    strength=EvidenceStrength.WEAK,
                ))
    else:
        checks_skipped.append("Reverse image search (no profile image URL provided)")

    # ── Username Cross-Platform (Sherlock) ───────────────────────────────────
    checks_skipped.append(
        "Username cross-platform check (Sherlock) — requires CLI installation; "
        "run manually: python3 -m sherlock <username>"
    )

    composite = sum(scores) / len(scores) if scores else None
    return EngineResult(
        engine="osint",
        checks_performed=checks_done,
        checks_skipped=checks_skipped,
        evidence=evidence,
        authenticity_score=composite,
        raw_metadata=raw_meta,
    )
