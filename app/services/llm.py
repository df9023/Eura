"""OpenAI LLM service for code analysis."""
import json
import uuid
from typing import List, Dict
from app.core.config import openai_client
from app.core.logger import logger
from app.models.domain import Finding, Evidence


def make_parse_failure_finding(file_path: str, raw_response: str) -> Finding:
    """Create a finding for LLM parse failures."""
    return Finding(
        id=str(uuid.uuid4()),
        title="LLM output parsing failed",
        severity="info",
        confidence=0.2,
        summary="The model did not return valid JSON.",
        details=raw_response[:2000] if raw_response else "Empty response from LLM",
        evidence=[Evidence(file=file_path)],
        recommendation="Retry the scan or adjust the prompt to force strict JSON output.",
        category="other",
    )


def normalize_findings(findings_in: List[Dict], file_path: str) -> List[Finding]:
    """Normalize and validate findings from LLM output."""
    findings: List[Finding] = []
    allowed_severities = {"high", "medium", "low", "info"}
    
    for f in findings_in:
        # Ensure evidence has file path
        evidence_items = []
        for ev in f.get("evidence", []) or []:
            evidence_items.append(
                Evidence(
                    file=ev.get("file") or file_path,  # Use file_path if missing
                    lines=ev.get("lines"),
                    snippet=ev.get("snippet"),
                )
            )
        if not evidence_items:
            evidence_items = [Evidence(file=file_path)]

        # Normalize severity
        severity = f.get("severity", "info").lower()
        if severity not in allowed_severities:
            severity = "info"

        # Clamp confidence
        confidence = float(f.get("confidence", 0.4))
        confidence = max(0.0, min(1.0, confidence))

        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                title=f.get("title", "Untitled finding") or "Untitled finding",
                severity=severity,
                confidence=confidence,
                summary=f.get("summary", "") or "",
                details=f.get("details", "") or "",
                evidence=evidence_items,
                recommendation=f.get("recommendation", "") or "",
                category=f.get("category"),
            )
        )

    return findings


async def analyze_file_with_llm(file_path: str, file_content: str) -> List[Finding]:
    """Analyze file with LLM, enforcing JSON output with retry."""
    system_prompt = """You are a security code auditor. Return ONLY valid JSON matching this exact schema:
{
  "findings": [
    {
      "title": "string",
      "severity": "high|medium|low|info",
      "confidence": 0.0-1.0,
      "summary": "1 sentence",
      "details": "short paragraph",
      "recommendation": "clear fix instruction",
      "category": "secrets|auth|crypto|injection|config|logging|dependency|other",
      "evidence": [
        { "file": "string", "lines": "string|null", "snippet": "string|null" }
      ]
    }
  ]
}

Rules:
- Return ONLY JSON, no markdown, no code blocks, no explanation.
- Only report issues you can justify from the provided code.
- If unsure, lower confidence and severity.
- If no issues, return {"findings": []}.
- Evidence snippets must be copied from the code (short).
- Every evidence entry must include "file" field."""

    user_prompt = f"File: {file_path}\n\nCode:\n{file_content}"

    # Try with JSON mode first (if supported), then fallback to prompt enforcement
    max_retries = 1
    for attempt in range(max_retries + 1):
        try:
            # Try with response_format="json_object" if available
            create_kwargs = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": 2000,
                "temperature": 0.2,
            }
            
            # Try to use JSON mode if available in the SDK
            try:
                create_kwargs["response_format"] = {"type": "json_object"}
            except (TypeError, AttributeError):
                # If response_format not supported, rely on prompt
                pass

            resp = await openai_client.chat.completions.create(**create_kwargs)
            raw = (resp.choices[0].message.content or "").strip()

            # Remove markdown code blocks if present
            if raw.startswith("```"):
                lines = raw.split("\n")
                if lines[0].startswith("```json") or lines[0].startswith("```"):
                    raw = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])

            # Parse JSON
            try:
                data = json.loads(raw)
                findings_in = data.get("findings", [])
                if not isinstance(findings_in, list):
                    findings_in = []
                
                return normalize_findings(findings_in, file_path)
            except json.JSONDecodeError as e:
                if attempt < max_retries:
                    logger.warning("JSON parse failed (attempt %d/%d) for %s, retrying: %s", 
                                  attempt + 1, max_retries + 1, file_path, str(e)[:100])
                    continue
                else:
                    logger.error("JSON parse failed after retries for %s: %s", file_path, str(e)[:100])
                    return [make_parse_failure_finding(file_path, raw)]
        except Exception as e:
            if attempt < max_retries:
                logger.warning("LLM call failed (attempt %d/%d) for %s, retrying: %s", 
                              attempt + 1, max_retries + 1, file_path, str(e)[:100])
                continue
            else:
                logger.error("LLM call failed after retries for %s: %s", file_path, str(e)[:100])
                return [make_parse_failure_finding(file_path, f"LLM error: {str(e)[:500]}")]

    # Should not reach here, but safety fallback
    return [make_parse_failure_finding(file_path, "Unknown error")]

