import re
from email import message_from_string

def analyze_header(header_text):
    # Parse the raw header text using Python's built-in email parser
    msg = message_from_string(header_text)

    sender = msg.get('From', 'Unknown')
    subject = msg.get('Subject', 'No subject')
    return_path = msg.get('Return-Path', '')
    auth_results = msg.get('Authentication-Results', '')

    # Check SPF, DKIM, DMARC from the Authentication-Results header
    spf = extract_auth_result(auth_results, 'spf')
    dkim = extract_auth_result(auth_results, 'dkim')
    dmarc = extract_auth_result(auth_results, 'dmarc')

    # Get the sender's IP from the Received header chain
    received_headers = msg.get_all('Received', [])
    from_ip = extract_ip(received_headers)

    reasons = []
    risk_score = 0

    if spf == 'FAIL':
        risk_score += 20
        reasons.append('SPF record failed — sender IP not authorized')
    if dkim == 'FAIL':
        risk_score += 20
        reasons.append('DKIM signature missing or invalid')
    if dmarc == 'FAIL':
        risk_score += 20
        reasons.append('DMARC policy violation detected')

    # Check if From domain matches Return-Path domain
    sender_domain = extract_domain(sender)
    return_path_domain = extract_domain(return_path)
    if sender_domain and return_path_domain and sender_domain != return_path_domain:
        risk_score += 15
        reasons.append(f'From domain "{sender_domain}" does not match Return-Path domain "{return_path_domain}"')

    # Check for suspicious keywords in subject line
    suspicious_keywords = ['verify', 'urgent', 'suspended', 'password', 'click here', 'confirm your account']
    subject_lower = subject.lower()
    matched = [k for k in suspicious_keywords if k in subject_lower]
    if matched:
        risk_score += 10 * len(matched)
        reasons.append(f'Suspicious keyword(s) found in subject: {", ".join(matched)}')

    risk_score = min(risk_score, 100)

    if not reasons:
        reasons.append('No phishing indicators detected — email passed all checks')

    verdict = 'phishing' if risk_score >= 50 else 'safe'
    confidence = min(100, risk_score + 10) if verdict == 'phishing' else min(100, 100 - risk_score)

    return {
        'verdict': verdict,
        'riskScore': risk_score,
        'confidence': confidence,
        'spf': spf,
        'dkim': dkim,
        'dmarc': dmarc,
        'sender': sender,
        'subject': subject,
        'fromIp': from_ip,
        'reasons': reasons
    }


def extract_auth_result(auth_header, mechanism):
    """Looks for spf=pass / dkim=fail / etc. inside the Authentication-Results header"""
    if not auth_header:
        return 'FAIL'
    match = re.search(rf'{mechanism}=(\w+)', auth_header, re.IGNORECASE)
    if match and match.group(1).lower() == 'pass':
        return 'PASS'
    return 'FAIL'


def extract_ip(received_headers):
    """Finds the first IPv4 address inside the Received header chain"""
    ip_pattern = r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?'
    for header in received_headers:
        match = re.search(ip_pattern, header)
        if match:
            return match.group(1)
    return 'Unknown'


def extract_domain(email_field):
    """Pulls the domain out of something like 'Name <user@domain.com>'"""
    match = re.search(r'@([\w.-]+)', email_field)
    return match.group(1).lower() if match else ''
def extract_email_fields(header_text):
    """Extracts basic identity + authentication fields from raw header text."""
    msg = message_from_string(header_text)

    auth_results = msg.get('Authentication-Results', '')

    return {
        "from": msg.get('From', ''),
        "to": msg.get('To', ''),
        "subject": msg.get('Subject', ''),
        "spf": extract_auth_result(auth_results, 'spf'),
        "dkim": extract_auth_result(auth_results, 'dkim'),
        "dmarc": extract_auth_result(auth_results, 'dmarc'),
    }