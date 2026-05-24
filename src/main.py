import re
import json
import os

# ============================================================
# SECURITY: Sanitize input to strip dangerous content
# like XSS scripts and SQL injection attempts
# ============================================================
def sanitize_text(text):
    # Remove HTML/script tags (XSS protection)
    text = re.sub(r'<[^>]+>', '', text)
    # Remove SQL injection patterns
    text = re.sub(r"('.*;?\s*--)", '', text, flags=re.IGNORECASE)
    return text

# ============================================================
# MASKING: Hide sensitive data in output for security
# e.g. 4532 0151 1283 4214 → **** **** **** 4214
# ============================================================
def mask_card(card):
    parts = card.split()
    return "**** **** **** " + parts[-1]

def mask_email(email):
    # e.g. john.doe@gmail.com → j*******@gmail.com
    local, domain = email.split("@")
    return local[0] + "*" * (len(local) - 1) + "@" + domain

# ============================================================
# REGEX PATTERNS - each one explained
# ============================================================

# Emails: standard format user@domain.ext
EMAIL_PATTERN = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'

# ALU-specific email validation
ALU_PATTERNS = {
    "official": r'[a-zA-Z0-9._%+\-]+@alueducation\.com$',
    "alumni":   r'[a-zA-Z0-9._%+\-]+@alumni\.alueducation\.com$',
    "si":       r'[a-zA-Z0-9._%+\-]+@si\.alueducation\.com$',
}

# Credit cards: 4 groups of 4 digits separated by spaces
CARD_PATTERN = r'\b\d{4} \d{4} \d{4} \d{4}\b'

# URLs: http or https links
URL_PATTERN = r'https?://[^\s\'"<>]+'

# Phone numbers: various international formats
PHONE_PATTERN = r'\+?[\d\s\-]{7,15}\d'

# Time: 12-hour (9:30 AM) and 24-hour (17:00)
TIME_PATTERN = r'\b([01]?\d|2[0-3]):[0-5]\d(\s?[APap][Mm])?\b'

# Hashtags: #word
HASHTAG_PATTERN = r'#[a-zA-Z]\w*'

# Currency: $1,250.00 or €320.50
CURRENCY_PATTERN = r'[\$€£]\d{1,3}(?:,\d{3})*(?:\.\d{2})'

# ============================================================
# CREDIT CARD VALIDATION (Luhn Algorithm)
# A real-world check used by payment systems to verify
# card numbers aren't just random digits
# ============================================================
def luhn_check(card_number):
    digits = [int(d) for d in card_number.replace(" ", "")]
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

# ============================================================
# CLASSIFY ALU EMAILS
# ============================================================
def classify_alu_email(email):
    if re.search(ALU_PATTERNS["si"], email):
        return "si"
    elif re.search(ALU_PATTERNS["alumni"], email):
        return "alumni"
    elif re.search(ALU_PATTERNS["official"], email):
        return "official"
    return None

# ============================================================
# MAIN EXTRACTION FUNCTION
# ============================================================
def extract_data(text):
    # Step 1: Sanitize first before doing anything
    clean_text = sanitize_text(text)

    # Step 2: Extract all matches using regex
    emails_raw     = re.findall(EMAIL_PATTERN, clean_text)
    cards_raw      = re.findall(CARD_PATTERN, clean_text)
    urls           = re.findall(URL_PATTERN, clean_text)
    phones         = re.findall(PHONE_PATTERN, clean_text)
    times          = re.findall(TIME_PATTERN, clean_text)
    hashtags       = re.findall(HASHTAG_PATTERN, clean_text)
    currencies     = re.findall(CURRENCY_PATTERN, clean_text)

    # Step 3: Validate and process emails
    validated_emails = []
    for email in emails_raw:
        # Skip obviously malformed emails
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            continue
        alu_type = classify_alu_email(email)
        validated_emails.append({
            "masked":    mask_email(email),
            "alu_type":  alu_type if alu_type else "external",
            "is_alu":    alu_type is not None
        })

    # Step 4: Validate credit cards using Luhn algorithm
    validated_cards = []
    for card in cards_raw:
        valid = luhn_check(card)
        validated_cards.append({
            "masked": mask_card(card),
            "luhn_valid": valid,
            "flagged": not valid
        })

    # Step 5: Clean up time tuples (regex returns groups)
    times_clean = [t[0] + (t[1].strip() if t[1] else "") for t in times]

    return {
        "emails":     validated_emails,
        "credit_cards": validated_cards,
        "urls":       list(set(urls)),       # remove duplicates
        "phones":     list(set(phones)),
        "times":      list(set(times_clean)),
        "hashtags":   list(set(hashtags)),
        "currencies": list(set(currencies)),
    }

# ============================================================
# RUN THE PROGRAM
# ============================================================
if __name__ == "__main__":
    # Build file paths relative to this script
    base_dir    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path  = os.path.join(base_dir, "input", "raw-text.txt")
    output_path = os.path.join(base_dir, "output", "sample-output.json")

    # Read the raw text
    with open(input_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    print("📄 Raw text loaded. Extracting data...\n")

    # Extract
    results = extract_data(raw_text)

    # Print summary to console
    print("✅ EXTRACTION COMPLETE")
    print(f"   Emails found:       {len(results['emails'])}")
    print(f"   Credit cards found: {len(results['credit_cards'])}")
    print(f"   URLs found:         {len(results['urls'])}")
    print(f"   Phone numbers:      {len(results['phones'])}")
    print(f"   Times found:        {len(results['times'])}")
    print(f"   Hashtags found:     {len(results['hashtags'])}")
    print(f"   Currencies found:   {len(results['currencies'])}")

    # Save to output JSON
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n💾 Output saved to: {output_path}")