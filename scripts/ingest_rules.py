#!/usr/bin/env python3
"""
Ingest CRA Rule Pack text file and convert to structured JSON matching schema_v0.1.json.

This script:
1. Reads eura_knowledge/cra_rule_pack_v0.1.txt
2. Parses each rule section
3. Uses LLM to convert rules to structured JSON matching the schema
4. Saves output as app/data/rules_db.json
"""

import json
import re
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from openai import OpenAI
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize OpenAI client
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY environment variable is required")

client = OpenAI(api_key=OPENAI_API_KEY)


def read_rule_pack(file_path: str) -> str:
    """Read the rule pack text file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def extract_rule_sections(text: str) -> List[Dict[str, str]]:
    """Extract individual rule sections from the text file."""
    rules = []
    
    # Pattern to match rule headers: "RULE CRA-BASE-XXX: Title"
    rule_pattern = re.compile(r"RULE (CRA-BASE-\d{3}): (.+?)\n={80,}")
    
    # Split text by rule sections
    sections = re.split(r"RULE CRA-BASE-\d{3}:", text)
    
    for i, section in enumerate(sections[1:], 1):  # Skip first section (intro)
        # Extract rule ID and title from the section header
        header_match = re.search(r"(CRA-BASE-\d{3}): (.+?)\n", section)
        if not header_match:
            continue
            
        rule_id = header_match.group(1)
        title = header_match.group(2).strip()
        
        # Find the end of this rule (next rule or remediation catalog)
        next_rule_match = re.search(r"\nRULE CRA-BASE-\d{3}:", section)
        remediation_match = re.search(r"\nREMEDIATION CATALOG", section)
        
        end_pos = len(section)
        if next_rule_match:
            end_pos = min(end_pos, next_rule_match.start())
        if remediation_match:
            end_pos = min(end_pos, remediation_match.start())
        
        rule_text = section[:end_pos].strip()
        
        rules.append({
            "rule_id": rule_id,
            "title": title,
            "content": rule_text
        })
    
    return rules


def extract_remediation_catalog(text: str) -> Dict[str, Dict[str, str]]:
    """Extract remediation catalog entries."""
    catalog = {}
    
    # Find remediation catalog section
    catalog_match = re.search(r"REMEDIATION CATALOG\n={80,}(.+?)\n={80,}", text, re.DOTALL)
    if not catalog_match:
        return catalog
    
    catalog_text = catalog_match.group(1)
    
    # Extract each REM-XXX entry
    rem_pattern = re.compile(r"REM-(\d{3}): (.+?)(?=\nREM-\d{3}:|\n={80,}|$)", re.DOTALL)
    
    for match in rem_pattern.finditer(catalog_text):
        rem_id = f"REM-{match.group(1)}"
        content = match.group(2).strip()
        
        # Parse the content into structured fields
        lines = content.split("\n")
        action = lines[0].strip("- ").strip() if lines else ""
        
        # Extract other fields if present
        catalog[rem_id] = {
            "remediation_id": rem_id,
            "action": action,
            "description": content
        }
    
    return catalog


def convert_rule_with_llm(rule_text: str, rule_id: str, title: str, schema_path: str) -> Dict[str, Any]:
    """Use LLM to convert a rule text into structured JSON matching the schema."""
    
    # Read schema for context
    with open(schema_path, "r") as f:
        schema = json.load(f)
    
    example_rule = schema.get("example_rule", {})
    example_signals = schema.get("example_signals", [])
    
    prompt = f"""You are converting a human-readable CRA compliance rule into structured JSON matching the EURA schema.

Rule ID: {rule_id}
Title: {title}

Rule Text:
{rule_text}

Schema Requirements:
- rule_id: "{rule_id}" (must match exactly)
- title: Short title (string)
- description_short: Brief description, max 200 characters (string)
- description_long: Detailed explanation (string, optional)
- regulation: "CRA" (must be exactly "CRA")
- applicability: Object with operator ("AND"/"OR"/"NOT") and conditions array
  - Conditions can reference signals (e.g., has_security_policy, dependency_count, has_dockerfile)
  - Use signal names from the example signals below
- required_evidence: Array of EvidenceSpec objects with type, source, required (boolean)
- check_method: One of ["repo_scan_static", "dependency_analysis", "file_presence", "content_analysis", "policy_attestation", "manual_review"]
- severity: Object with impact ("critical"/"high"/"medium"/"low"), likelihood ("high"/"medium"/"low"), overall ("critical"/"high"/"medium"/"low"/"info")
- remediation_ids: Array of strings matching pattern "REM-XXX" (extract from rule text)
- references: Object with article (string), annex (string, optional), note (string, optional)
- version: "0.1"

Example Rule Structure:
{json.dumps(example_rule, indent=2)}

Available Signals (use these in applicability conditions):
{json.dumps([s["name"] for s in example_signals], indent=2)}

Instructions:
1. Extract the remediation ID(s) mentioned in the rule text (REM-XXX format)
2. Build applicability conditions based on "When it applies" and "What EURA can check automatically" sections
3. Build required_evidence from "What EURA can check automatically" and "Suggested evidence artifacts"
4. Determine check_method from the rule content
5. Set severity based on the rule's importance (critical/high/medium/low)
6. Extract CRA article references from "References:" line
7. Keep description_short under 200 characters

Return ONLY valid JSON matching the Rule schema. Do not include markdown formatting."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a compliance engineer converting rules to structured JSON. Always return valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            response_format={"type": "json_object"}
        )
        
        result_text = response.choices[0].message.content.strip()
        
        # Remove markdown code blocks if present
        if result_text.startswith("```"):
            result_text = re.sub(r"^```(?:json)?\n", "", result_text)
            result_text = re.sub(r"\n```$", "", result_text)
        
        # Try to parse JSON, with fallback for common issues
        try:
            rule_json = json.loads(result_text)
        except json.JSONDecodeError as e:
            print(f"    Warning: JSON parse error for {rule_id}, attempting to fix...")
            # Try to extract JSON from the response
            json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
            if json_match:
                rule_json = json.loads(json_match.group(0))
            else:
                raise e
        
        # Ensure required fields are present
        rule_json["rule_id"] = rule_id
        rule_json["title"] = title
        rule_json["regulation"] = "CRA"
        rule_json["version"] = "0.1"
        
        # Ensure description_short is under 200 chars
        if "description_short" in rule_json and len(rule_json["description_short"]) > 200:
            rule_json["description_short"] = rule_json["description_short"][:197] + "..."
        
        return rule_json
        
    except Exception as e:
        print(f"Error converting rule {rule_id} with LLM: {e}")
        # Return a minimal valid rule structure
        return {
            "rule_id": rule_id,
            "title": title,
            "description_short": f"Rule {rule_id}: {title}",
            "regulation": "CRA",
            "applicability": {
                "operator": "AND",
                "conditions": []
            },
            "required_evidence": [],
            "check_method": "repo_scan_static",
            "severity": {
                "overall": "medium"
            },
            "remediation_ids": [],
            "references": {},
            "version": "0.1"
        }


def build_rules_database(rules: List[Dict[str, Any]], remediation_catalog: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    """Build the complete rules database JSON structure."""
    return {
        "schema_version": "0.1",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "description": "EURA CRA Compliance Rules Database - Generated from cra_rule_pack_v0.1.txt",
        "rules": rules,
        "remediation_catalog": remediation_catalog,
        "metadata": {
            "source_file": "eura_knowledge/cra_rule_pack_v0.1.txt",
            "rule_count": len(rules),
            "remediation_count": len(remediation_catalog)
        }
    }


def main():
    """Main execution function."""
    # Paths
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    rule_pack_path = project_root / "eura_knowledge" / "cra_rule_pack_v0.1.txt"
    schema_path = project_root / "eura_knowledge" / "schema_v0.1.json"
    output_path = project_root / "app" / "data" / "rules_db.json"
    
    # Validate input files exist
    if not rule_pack_path.exists():
        print(f"Error: Rule pack file not found: {rule_pack_path}")
        sys.exit(1)
    
    if not schema_path.exists():
        print(f"Error: Schema file not found: {schema_path}")
        sys.exit(1)
    
    print(f"Reading rule pack from: {rule_pack_path}")
    rule_pack_text = read_rule_pack(str(rule_pack_path))
    
    print("Extracting rule sections...")
    rule_sections = extract_rule_sections(rule_pack_text)
    print(f"Found {len(rule_sections)} rules")
    
    print("Extracting remediation catalog...")
    remediation_catalog = extract_remediation_catalog(rule_pack_text)
    print(f"Found {len(remediation_catalog)} remediation entries")
    
    print("\nConverting rules to structured JSON using LLM...")
    structured_rules = []
    
    for i, rule_section in enumerate(rule_sections, 1):
        rule_id = rule_section["rule_id"]
        title = rule_section["title"]
        content = rule_section["content"]
        
        print(f"  [{i}/{len(rule_sections)}] Converting {rule_id}...")
        
        structured_rule = convert_rule_with_llm(
            content,
            rule_id,
            title,
            str(schema_path)
        )
        
        structured_rules.append(structured_rule)
    
    print("\nBuilding rules database...")
    rules_db = build_rules_database(structured_rules, remediation_catalog)
    
    print(f"Writing output to: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(rules_db, f, indent=2, ensure_ascii=False)
    
    # Validate output
    print("\nValidating output...")
    if len(structured_rules) != 18:
        print(f"  Warning: Expected 18 rules, found {len(structured_rules)}")
    
    # Check that all rules have required fields
    missing_fields = []
    for rule in structured_rules:
        required = ["rule_id", "title", "description_short", "regulation", "applicability", "check_method", "severity"]
        for field in required:
            if field not in rule:
                missing_fields.append(f"{rule.get('rule_id', 'unknown')}: missing {field}")
    
    if missing_fields:
        print(f"  Warning: Some rules are missing required fields:")
        for msg in missing_fields[:5]:  # Show first 5
            print(f"    - {msg}")
    else:
        print("  ✓ All rules have required fields")
    
    file_size_kb = output_path.stat().st_size / 1024
    
    print(f"\n✓ Successfully created rules database with {len(structured_rules)} rules")
    print(f"  Output: {output_path}")
    print(f"  Remediation entries: {len(remediation_catalog)}")
    print(f"  File size: {file_size_kb:.1f} KB")


if __name__ == "__main__":
    main()

