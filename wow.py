import json
import re
import os

# ─── Configuration ────────────────────────────────────────────────────────────

INPUT_JSON  = "testing/yash.json"
OUTPUT_JSON = "text_threat_analysis_output.json"

# Threat categories and their trigger regex patterns
THREAT_KEYWORDS = {
    "Financial fraud": [
        r"\bbank card\b",
        r"\bapproval code\b",
        r"\bcash receipt\b",
        r"\btotal\b",
        r"\bcash\b",
        r"\bchange\b"
    ],
    "Identity theft": [
        r"\baadhar\b",
        r"\bpan\b",
        r"\bpassport\b",
        r"\bssn\b",
        r"\bdl\b"
    ],
    "Weapons/Violence": [
        r"\bknife\b",
        r"\bgun\b",
        r"\brifle\b",
        r"\bgrenade\b",
        r"\bexplosive\b"
    ],
    "Drugs/Illegal": [
        r"\bcocaine\b",
        r"\bweed\b",
        r"\bheroin\b",
        r"\bmeth\b"
    ],
    "Explicit content": [
        r"\bxxx\b",
        r"\bnsfw\b",
        r"\b18\+\b"
    ],
    "Terrorism": [
        r"\bbomb\b",
        r"\battack\b",
        r"\bisis\b",
        r"\brecruitment\b"
        r"\brifle\b"
    ],
    "Surveillance": [
        r"\blocation\b",
        r"\brecording\b",
        r"\bcamera\b",
        r"\btracking\b"
    ],
    "Encrypted/Hidden": [
        r"\bencrypted\b",
        r"\bpassword-protected\b",
        r"\bstego\b",
        r"\bsteganography\b"
    ]
}

# Sensitive entity regexes
EMAIL_RE        = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
URL_RE          = re.compile(r"https?://[^\s]+")
PHONE_RE        = re.compile(r"\b\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{4}\b")
CREDIT_CARD_RE  = re.compile(r"\b(?:\d[ -]*?){13,16}\b")

# Pre‑compile keyword patterns
COMPILED_THREATS = {
    cat: [re.compile(pat, re.IGNORECASE) for pat in pats]
    for cat, pats in THREAT_KEYWORDS.items()
}

# ─── Detection Helpers ─────────────────────────────────────────────────────────

def detect_keywords(text):
    """Return (categories, keywords) found via regex."""
    cats = set()
    keys = []
    for cat, patterns in COMPILED_THREATS.items():
        for pat in patterns:
            for m in pat.findall(text):
                cats.add(cat)
                keys.append(m)
    return list(cats), keys

def detect_entities(text):
    """Return list of found entities with type labels."""
    ents = []
    for label, regex in [
        ("email", EMAIL_RE),
        ("url", URL_RE),
        ("phone", PHONE_RE),
        ("credit_card", CREDIT_CARD_RE)
    ]:
        for m in regex.findall(text):
            ents.append({"type": label, "value": m})
    return ents

def compute_score(num_keys, num_ents):
    """Simple weighted score."""
    return num_keys + 2 * num_ents

# ─── Main Analysis ─────────────────────────────────────────────────────────────

def analyze_json(input_path, output_path):
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        data = [data]

    results = []
    for entry in data:
        # support both "path" and "file_path"
        file_path = entry.get("path") or entry.get("file_path") or "unknown"
        # extract text
        content = entry.get("content", "")
        text = content.get("text", "") if isinstance(content, dict) else content

        # run detectors
        cats, keys = detect_keywords(text)
        ents = detect_entities(text)
        score = compute_score(len(keys), len(ents))
        threat = score > 0
        summary = (
            "No threats detected."
            if not threat
            else f"Detected threats in categories: {', '.join(cats)} (score {score})."
        )

        results.append({
            "file": file_path,
            "text": text,
            "entities": ents,
            "predicted_threats": {
                "threat_detected": threat,
                "score": score,
                "categories": cats,
                "keywords": keys,
                "summary": summary
            }
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"✅ Analysis complete. Results saved to {output_path}")

# ─── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    analyze_json(INPUT_JSON, OUTPUT_JSON)
