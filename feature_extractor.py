import re
from email import message_from_string
from email.utils import parseaddr

# Keywords we flag in the subject line. This list does NOT decide phishing/safe
# on its own - it's just one more feature for the ML model to learn from later.
SUSPICIOUS_KEYWORDS = [
    'urgent', 'verify', 'password', 'account', 'suspended',
    'security', 'payment', 'click', 'confirm', 'update'
]


def get_domain(email_field):
    """
    Pulls just the domain out of a header value.
    Example: 'John <john@example.com>' -> 'example.com'
    Returns '' if there's no valid email address in the field.
    """
    if not email_field:
        return ''
    _, addr = parseaddr(email_field)  # parseaddr splits "Name" and "email@domain"
    if '@' in addr:
        return addr.split('@')[-1].lower()
    return ''


def get_auth_value(auth_header, mechanism):
    """
    Reads the spf / dkim / dmarc result out of the Authentication-Results header.

    Example Authentication-Results header:
    "mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=fail; dmarc=none"

    Returns one of: PASS, FAIL, NONE, UNKNOWN
    Important: if the header is missing entirely, we return UNKNOWN -
    NOT FAIL. A missing result just means we don't know, it is not proof
    of a failure.
    """
    if not auth_header:
        return 'UNKNOWN'

    match = re.search(rf'{mechanism}=(\w+)', auth_header, re.IGNORECASE)
    if not match:
        return 'UNKNOWN'

    value = match.group(1).upper()
    if value in ('PASS', 'FAIL', 'NONE'):
        return value
    return 'UNKNOWN'


def extract_received_info(received_headers):
    """
    Goes through every 'Received:' header and pulls out:
    - IP addresses of servers that handled the email (sender_ips)
    - hostnames mentioned in each hop (mail_hostnames)

    An email usually passes through several mail servers before reaching you.
    Each server adds its own 'Received:' line on top - like a stack of
    postmarks on a physical letter, oldest at the bottom.
    """
    ip_pattern = r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?'
    hostname_pattern = r'from\s+([^\s]+)'

    ips = []
    hostnames = []

    for header in received_headers:
        ip_match = re.search(ip_pattern, header)
        if ip_match and ip_match.group(1) not in ips:
            ips.append(ip_match.group(1))

        host_match = re.search(hostname_pattern, header, re.IGNORECASE)
        if host_match:
            hostnames.append(host_match.group(1))

    return ips, hostnames


def find_suspicious_keywords(subject):
    """Returns the list of suspicious words found in the subject line (lowercase match)."""
    subject_lower = (subject or '').lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in subject_lower]


def extract_features(header_text):
    """
    Main function of this module.

    Input: raw email header text (a string)
    Output: a clean dictionary of features, ready to be:
      1) shown to the user, and later
      2) fed into an ML model as training/prediction input

    This function does NOT decide phishing or safe. It only extracts facts.
    """
    msg = message_from_string(header_text or '')

    # ---- A. Identity fields ----
    from_ = msg.get('From', '') or ''
    to_ = msg.get('To', '') or ''
    reply_to = msg.get('Reply-To', '') or ''
    return_path = msg.get('Return-Path', '') or ''
    subject = msg.get('Subject', '') or ''
    message_id = msg.get('Message-ID', '') or ''
    date = msg.get('Date', '') or ''

    from_domain = get_domain(from_)
    reply_to_domain = get_domain(reply_to)
    return_path_domain = get_domain(return_path)

    # ---- B. Authentication fields ----
    auth_results = msg.get('Authentication-Results', '') or ''
    spf = get_auth_value(auth_results, 'spf')
    dkim = get_auth_value(auth_results, 'dkim')
    dmarc = get_auth_value(auth_results, 'dmarc')

    # ---- C. Received / routing fields ----
    # get_all() returns a list because an email can have MANY Received headers
    received_headers = msg.get_all('Received', []) or []
    hop_count = len(received_headers)
    sender_ips, mail_hostnames = extract_received_info(received_headers)

    # ---- D. Derived security features ----
    # Only flag a mismatch if the domain actually exists in that field.
    from_reply_to_mismatch = bool(reply_to_domain) and reply_to_domain != from_domain
    from_return_path_mismatch = bool(return_path_domain) and return_path_domain != from_domain

    suspicious_keywords = find_suspicious_keywords(subject)

    return {
        "from": from_,
        "to": to_,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "message_id": message_id,
        "date": date,

        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,

        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,

        "hop_count": hop_count,
        "sender_ips": sender_ips,
        "received_headers": received_headers,
        "mail_hostnames": mail_hostnames,

        "from_reply_to_mismatch": from_reply_to_mismatch,
        "from_return_path_mismatch": from_return_path_mismatch,

        "suspicious_keywords": suspicious_keywords
    }