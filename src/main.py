import re
import json
import os

# ============================================================
# SECURITY SANITIZATION
# We clean the input BEFORE any processing to protect against:
# - XSS: <script>alert('xss')</script> style attacks
# - SQL Injection: '; DROP TABLE tickets; -- style attacks
# We log what we removed so the output shows we caught it
# ============================================================
def sanitize_text(text):
    flagged = []

    # Detect and remove HTML/script tags (XSS protection)
    xss_matches = re.findall(r'<[^>]+>', text)
    if xss_matches:
        flagged.append({
            "type": "XSS attempt",
            "content": xss_matches
        })
    text = re.sub(r'<[^>]+>', '', text)

    # Detect and remove SQL injection patterns
    sql_matches = re.findall(r"(\'[^\']*;?\s*--[^\n]*)", text)
    if sql_matches:
        flagged.append({
            "type": "SQL injection attempt",
            "content": sql_matches
        })
    text = re.sub(r"(\'[^\']*;?\s*--[^\n]*)", '', text, flags=re.IGNORECASE)

    # Detect and remove javascript: pseudo-URLs
    js_matches = re.findall(r'javascript:[^\s\'"]+', text)
    if js_matches:
        flagged.append({
            "type": "JavaScript injection attempt",
            "content": js_matches
        })
    text = re.sub(r'javascript:[^\s\'"]+', '', text)

    return text, flagged


# ============================================================
# MASKING SENSITIVE DATA
# We never expose full card numbers or emails in output.
# This mimics real-world PCI-DSS and privacy compliance.
# e.g. 4532 0151 1283 4214 → **** **** **** 4214
# e.g. john.doe@gmail.com  → j*******@gmail.com
# ============================================================
def mask_card(card):
    parts = card.split()
    return "**** **** **** " + parts[-1]

def mask_email(email):
    local, domain = email.split("@")
    return local[0] + "*" * (len(local) - 1) + "@" + domain


# ============================================================
# REGEX PATTERNS — explained line by line
# ============================================================

# EMAIL: local@domain.tld
# [a-zA-Z0-9._%+\-]+ = local part (letters, digits, dots, etc.)
# @                   = literal @ symbol
# [a-zA-Z0-9.\-]+     = domain name
# \.[a-zA-Z]{2,}      = dot + top-level domain (min 2 chars)
EMAIL_PATTERN = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'

# ALU-SPECIFIC EMAIL VALIDATION
# Must match exactly these domains — nothing else accepted
ALU_PATTERNS = {
    "official": r'^[a-zA-Z0-9._%+\-]+@alueducation\.com$',
    "alumni":   r'^[a-zA-Z0-9._%+\-]+@alumni\.alueducation\.com$',
    "si":       r'^[a-zA-Z0-9._%+\-]+@si\.alueducation\.com$',
}

# CREDIT CARD: exactly 4 groups of 4 digits separated by spaces
# \b         = word boundary (prevents partial matches)
# \d{4}      = exactly 4 digits
# (space)    = literal space between groups
CARD_PATTERN = r'\b\d{4} \d{4} \d{4} \d{4}\b'

# URL: http or https web addresses
# https?     = http or https
# ://        = literal ://
# [^\s\'"<>]+ = any chars except whitespace, quotes, brackets
URL_PATTERN = r'https?://[^\s\'"<>]+'

# PHONE: international format numbers
# \+?        = optional leading + (for country codes)
# [\d\s\-]   = digits, spaces, or hyphens
# {7,15}     = between 7 and 15 characters total
# \d         = must end in a digit
PHONE_PATTERN = r'\+?[\d][\d\s\-]{6,17}\d'

# TIME: both 12-hour (9:30 AM) and 24-hour (17:00)
# [01]?\d    = hour: optional leading 0/1 + digit (for 12hr)
# 2[0-3]     = hour: 20-23 (for 24hr)
# :[0-5]\d   = colon + minutes 00-59
# (\s?[APap][Mm])? = optional AM/PM suffix
TIME_PATTERN = r'\b([01]?\d|2[0-3]):[0-5]\d(\s?[APap][Mm])?\b'

# HASHTAG: # followed by a word (no spaces)
# #          = literal hash
# [a-zA-Z]   = must start with a letter (not a number)
# \w*        = followed by any word characters
HASHTAG_PATTERN = r'#[a-zA-Z]\w*'

# CURRENCY: dollar, euro, or pound amounts
# [\$€£]              = currency symbol
# \d{1,3}             = 1-3 digits before first comma
# (?:,\d{3})*         = optional groups of ,000
# (?:\.\d{2})         = required decimal .00
CURRENCY_PATTERN = r'[\$€£]\d{1,3}(?:,\d{3})*(?:\.\d{2})'


# ============================================================
# CREDIT CARD VALIDATION — Luhn Algorithm
# Used by real payment systems (Visa, Mastercard) to verify
# a card number isn't just random digits.
# How it works:
#   1. Reverse the digits
#   2. Double every second digit
#   3. If doubled value > 9, subtract 9
#   4. Sum all digits — valid if divisible by 10
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
# EMAIL VALIDATION
# First checks it's a properly formed email (has @, domain, tld)
# Then checks if it belongs to an ALU domain
# ============================================================
def is_valid_email(email):
    # Must have exactly one @, a domain, and a tld
    return bool(re.match(r'^[^@]+@[^@]+\.[^@]{2,}$', email))

def classify_alu_email(email):
    # Check most specific domains first (si, alumni) before general
    if re.match(ALU_PATTERNS["si"], email):
        return "si"
    elif re.match(ALU_PATTERNS["alumni"], email):
        return "alumni"
    elif re.match(ALU_PATTERNS["official"], email):
        return "official"
    return None


# ============================================================
# MAIN EXTRACTION FUNCTION
# ============================================================
def extract_data(text):
    # --- STEP 1: Sanitize input and log any threats found ---
    clean_text, security_flags = sanitize_text(text)

    # --- STEP 2: Extract raw matches using regex patterns ---
    emails_raw  = re.findall(EMAIL_PATTERN, clean_text)
    cards_raw   = re.findall(CARD_PATTERN, clean_text)
    urls_raw    = re.findall(URL_PATTERN, clean_text)
    phones_raw  = re.findall(PHONE_PATTERN, clean_text)
    times_raw   = re.findall(TIME_PATTERN, clean_text)
    hashtags    = list(set(re.findall(HASHTAG_PATTERN, clean_text)))
    currencies  = list(set(re.findall(CURRENCY_PATTERN, clean_text)))

    # --- STEP 3: Validate emails ---
    validated_emails = []
    rejected_emails  = []
    for email in emails_raw:
        if not is_valid_email(email):
            # Log malformed emails as rejected
            rejected_emails.append({
                "value": email,
                "reason": "Malformed email address"
            })
            continue
        alu_type = classify_alu_email(email)
        validated_emails.append({
            "masked":   mask_email(email),
            "alu_type": alu_type if alu_type else "external",
            "is_alu":   alu_type is not None
        })

    # --- STEP 4: Validate credit cards ---
    validated_cards = []
    rejected_cards  = []
    for card in cards_raw:
        if luhn_check(card):
            validated_cards.append({
                "masked":     mask_card(card),
                "luhn_valid": True
            })
        else:
            # Flag invalid cards explicitly — don't silently drop them
            rejected_cards.append({
                "masked": mask_card(card),
                "luhn_valid": False,
                "reason": "Failed Luhn algorithm check — likely fake or test card"
            })

    # --- STEP 5: Filter suspicious URLs ---
    # Only keep http/https URLs (javascript: already stripped in sanitize)
    valid_urls = []
    flagged_urls = []
    for url in set(urls_raw):
        if re.match(r'https?://', url):
            valid_urls.append(url)
        else:
            flagged_urls.append({
                "value": url,
                "reason": "Non-HTTP protocol — potentially unsafe"
            })

    # --- STEP 6: Clean up phone numbers ---
    # Filter out numbers that are too short or look like IDs/ticket numbers
    valid_phones = []
    for p in set(phones_raw):
        digits_only = re.sub(r'\D', '', p)
        if len(digits_only) >= 7:
            valid_phones.append(p.strip())

    # --- STEP 7: Clean up time matches (regex returns tuples) ---
    times_clean = list(set([
        t[0] + (t[1].strip() if t[1] else "") for t in times_raw
    ]))

    return {
        "summary": {
            "emails_found":       len(validated_emails),
            "cards_valid":        len(validated_cards),
            "cards_invalid":      len(rejected_cards),
            "urls_found":         len(valid_urls),
            "phones_found":       len(valid_phones),
            "times_found":        len(times_clean),
            "hashtags_found":     len(hashtags),
            "currencies_found":   len(currencies),
            "security_flags":     len(security_flags),
            "rejected_emails":    len(rejected_emails),
        },
        "extracted": {
            "emails":      validated_emails,
            "credit_cards": {
                "valid":   validated_cards,
                "invalid": rejected_cards
            },
            "urls":        valid_urls,
            "phones":      valid_phones,
            "times":       times_clean,
            "hashtags":    hashtags,
            "currencies":  currencies,
        },
        "security": {
            "threats_detected": security_flags,
            "flagged_urls":     flagged_urls,
            "rejected_emails":  rejected_emails,
        }
    }


# ============================================================
# RUN THE PROGRAM
# ============================================================
if __name__ == "__main__":
    base_dir    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path  = os.path.join(base_dir, "input", "raw-text.txt")
    output_path = os.path.join(base_dir, "output", "sample-output.json")

    with open(input_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    print("📄 Raw text loaded. Extracting data...\n")

    results = extract_data(raw_text)
    s = results["summary"]

    print("✅ EXTRACTION COMPLETE")
    print(f"   Emails found:          {s['emails_found']}")
    print(f"   Emails rejected:       {s['rejected_emails']}")
    print(f"   Credit cards (valid):  {s['cards_valid']}")
    print(f"   Credit cards (invalid):{s['cards_invalid']}")
    print(f"   URLs found:            {s['urls_found']}")
    print(f"   Phone numbers:         {s['phones_found']}")
    print(f"   Times found:           {s['times_found']}")
    print(f"   Hashtags found:        {s['hashtags_found']}")
    print(f"   Currencies found:      {s['currencies_found']}")
    print(f"\n🚨 Security threats detected: {s['security_flags']}")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n💾 Output saved to: {output_path}")