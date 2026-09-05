import re
import datetime
from email import message_from_string
from email.utils import parsedate_to_datetime


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

    # Build the hop-by-hop path from the Received header chain first,
    # so we can derive fromIp from the same oldest->newest ordering.
    auth_all_pass = spf == 'PASS' and dkim == 'PASS' and dmarc == 'PASS'
    hops = extract_hops(received_headers := msg.get_all('Received', []))
    for hop in hops:
        hop['status'] = classify_hop_status(hop['server'], auth_all_pass)

    # Get the sender's IP from the oldest hop (closest to the real sender)
    from_ip = extract_ip(received_headers)

    reasons = []
    risk_score = 0

    # Fold hop-level risk into the overall score so verdict/UI can't disagree with the route view.
    # Hop classification is a weak heuristic compared to SPF/DKIM/DMARC, so:
    #  - cap its total contribution instead of letting it scale unbounded with hop count
    #  - skip it entirely when all three auth checks already passed, since a passing
    #    DMARC-aligned message already proves the delivery path was authorized
    danger_hops = [h for h in hops if h['status'] == 'danger']
    warning_hops = [h for h in hops if h['status'] == 'warning']

    if danger_hops:
        risk_score += 25
        servers = ', '.join(h['server'] for h in danger_hops)
        reasons.append(f'Unverified/unresolvable server(s) in delivery path: {servers}')
    if warning_hops and not auth_all_pass:
        hop_risk = min(10 * len(warning_hops), 20)  # capped, not unbounded per-hop
        risk_score += hop_risk
        servers = ', '.join(h['server'] for h in warning_hops)
        reasons.append(f'Untrusted relay(s) in delivery path: {servers}')

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
        'reasons': reasons,
        'hops': hops
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
    """
    Finds the sender's IP by walking the Received chain oldest-first
    (same ordering extract_hops uses), so we report the IP closest to
    the real sender rather than the first IP found in the newest
    (recipient-side) hop.
    """
    ip_pattern = r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?'
    private_prefixes = ('10.', '192.168.', '127.')
    for header in reversed(received_headers):  # oldest (closest to sender) first
        match = re.search(ip_pattern, header)
        if match:
            ip = match.group(1)
            if ip.startswith(private_prefixes) or _is_private_172(ip):
                continue
            return ip
    return 'Unknown'


def _is_private_172(ip):
    """172.16.0.0 - 172.31.255.255 is a private range"""
    parts = ip.split('.')
    if len(parts) != 4 or parts[0] != '172':
        return False
    try:
        second = int(parts[1])
    except ValueError:
        return False
    return 16 <= second <= 31


def extract_domain(email_field):
    """Pulls the domain out of something like 'Name <user@domain.com>'"""
    match = re.search(r'@([\w.-]+)', email_field)
    return match.group(1).lower() if match else ''


def extract_hops(received_headers):
    """
    Turns the Received: header chain into an ordered list of hops.
    Received headers appear newest-first, so we reverse to get
    sender -> recipient order.
    """
    hops = []
    headers = list(reversed(received_headers))
    timestamps = []

    for h in headers:
        server = extract_hop_server(h)
        ts = extract_hop_timestamp(h)
        timestamps.append(ts)
        hops.append({'server': server, 'timestamp': ts.isoformat() if ts else None})

    for i, hop in enumerate(hops):
        if i == 0 or timestamps[i] is None or timestamps[i - 1] is None:
            hop['delayMs'] = 0
        else:
            hop['delayMs'] = int((timestamps[i] - timestamps[i - 1]).total_seconds() * 1000)

    return hops


def extract_hop_server(h):
    """Best-effort server name from a Received header line."""
    # 1) Prefer a real dotted domain after from/by, e.g. mail.google.com
    domain_match = re.search(r'(?:from|by)\s+([\w.-]+\.[a-zA-Z]{2,})', h)
    if domain_match:
        return domain_match.group(1)

    # 2) Otherwise take whatever token follows "from" (could be an internal
    #    ID, base64 string, or IPv6-style address with no readable domain)
    from_match = re.search(r'from\s+([^\s(]+)', h)
    if from_match:
        token = from_match.group(1)
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', h)
        return f'{token} [{ip_match.group(1)}]' if ip_match else token

    # 3) No "from" at all -- fall back to the "by" target
    by_match = re.search(r'by\s+([^\s(]+)', h)
    if by_match:
        return by_match.group(1)

    return 'Unknown server'


def extract_hop_timestamp(h):
    """Finds and parses the date in a Received header, whether or not it's
    after a semicolon, and handles both RFC 2822 dates and the ISO-style
    dates some servers use (e.g. SendGrid's internal relay)."""
    # RFC 2822 style: "Fri, 04 Sep 2026 14:54:02 +0000"
    rfc_match = re.search(
        r'([A-Za-z]{3},\s*\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2})(?:\.\d+)?\s*([+-]\d{4})?',
        h
    )
    if rfc_match:
        date_str, tz = rfc_match.group(1), rfc_match.group(2) or '+0000'
        try:
            return parsedate_to_datetime(f'{date_str} {tz}')
        except Exception:
            pass

    # ISO style: "2026-09-04 14:54:02.803534809 +0000"
    iso_match = re.search(
        r'(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?\s*([+-]\d{4})?', h
    )
    if iso_match:
        date_part, time_part, tz = iso_match.groups()
        tz = tz or '+0000'
        try:
            return datetime.datetime.strptime(f'{date_part} {time_part} {tz}', '%Y-%m-%d %H:%M:%S %z')
        except Exception:
            return None

    return None


def classify_hop_status(server, auth_all_pass=False):
    """
    Classify a hop as safe / warning / danger.

    - 'safe': a known big-provider domain, OR any real-looking domain
      when SPF+DKIM+DMARC all passed (a passing DMARC-aligned message
      already proves the delivery path was authorized).
    - 'warning': a real-looking domain we can't vouch for and auth
      didn't fully pass, or an unresolved/unknown token.
    - 'danger': reserved for cases with no server info at all.
    """
    trusted_domains = ['gmail.com', 'google.com', 'outlook.com', 'microsoft.com']

    # server may look like "host.name" or "host.name [1.2.3.4]" — isolate the hostname part
    host = server.lower().split(' ')[0].strip('[]')

    if any(host == d or host.endswith('.' + d) for d in trusted_domains):
        return 'safe'

    if server == 'Unknown server':
        return 'warning'

    if _looks_like_real_domain(host):
        # A real domain we don't explicitly trust — only vouch for it if
        # the message's own authentication already passed end-to-end.
        return 'safe' if auth_all_pass else 'warning'

    # Internal IDs, base64 blobs, IPv6-style routing addresses, pod names, etc.
    # — no domain to check, so we can't verify it either way.
    return 'warning'


def _looks_like_real_domain(host):
    """
    Rough check for 'is this actually a hostname' vs an internal ID/IPv6
    address/pod name. Real domains: 2+ labels, a plausible TLD, and no
    colons (which would indicate an IPv6-style address, not a hostname).
    """
    if ':' in host:
        return False
    labels = host.split('.')
    if len(labels) < 2:
        return False
    tld = labels[-1]
    return tld.isalpha() and 2 <= len(tld) <= 24


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