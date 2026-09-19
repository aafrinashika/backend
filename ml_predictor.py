import joblib
import pandas as pd

_bundle = joblib.load('phishshield_model.pkl')
_model = _bundle['model']
_columns = _bundle['columns']


def _map_auth_result(value, allowed_suffixes):
    """
    feature_extractor.py PASS/FAIL/NONE/UNKNOWN kudukum.
    Namma training data fail/neutral/pass (or fail/none/pass) categories use pannirukom.
    PASS matches directly. FAIL = baseline (all-zero). NONE/UNKNOWN = closest available category.
    """
    value = (value or '').upper()
    if value == 'PASS' and 'pass' in allowed_suffixes:
        return 'pass'
    if value == 'NONE' and 'none' in allowed_suffixes:
        return 'none'
    if value in ('NONE', 'UNKNOWN') and 'neutral' in allowed_suffixes:
        return 'neutral'
    return None  # FAIL -> baseline


def predict_from_extracted(features: dict):
    print("DEBUG - raw features:", features)
    """
    Input: feature_extractor.extract_features() kudukura dict
    Output: {'prediction': 'Safe'/'Phishing', 'probability_safe': ..., 'probability_phishing': ...}
    """
    row = {col: 0 for col in _columns}

    row['num_received_headers'] = features.get('hop_count', 0)
    row['reply_to_present'] = 1 if features.get('reply_to') else 0

    spf_suffix = _map_auth_result(features.get('spf'), {'neutral', 'pass'})
    if spf_suffix:
        row[f'spf_result_{spf_suffix}'] = 1

    dkim_suffix = _map_auth_result(features.get('dkim'), {'neutral', 'pass'})
    if dkim_suffix:
        row[f'dkim_result_{dkim_suffix}'] = 1

    dmarc_suffix = _map_auth_result(features.get('dmarc'), {'none', 'pass'})
    if dmarc_suffix:
        row[f'dmarc_result_{dmarc_suffix}'] = 1

    domain_col = f"from_domain_{features.get('from_domain', '')}"
    if domain_col in row:
        row[domain_col] = 1
    # trained domain list-la illaatha domain-na, ella from_domain_* um 0-ah irukkum (fine)

    X_new = pd.DataFrame([row])[_columns]
    pred = _model.predict(X_new)[0]
    proba = _model.predict_proba(X_new)[0]

    return {
        'prediction': 'Phishing' if pred == 1 else 'Safe',
        'probability_safe': round(float(proba[0]), 4),
        'probability_phishing': round(float(proba[1]), 4)
    }