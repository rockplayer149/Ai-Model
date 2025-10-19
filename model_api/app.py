from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import numpy as np
import re
import email
from scipy.sparse import hstack, csr_matrix
import warnings
import os
warnings.filterwarnings('ignore')

# --- CONFIGURE THIS ---
MODEL_PATH = "enhanced_email_classifier.pkl"
# -------------------------

app = Flask(__name__)
CORS(app)

# Global variables for model
model = None
vectorizer = None
scaler = None
feature_columns = None

# ============================================
# FEATURE EXTRACTION (EMBEDDED IN APP.PY)
# ============================================

TRUSTED_DOMAINS = {
    'tech': ['google.com', 'gmail.com', 'microsoft.com', 'outlook.com', 'apple.com', 'icloud.com'],
    'banking': ['chase.com', 'wellsfargo.com', 'bankofamerica.com', 'paypal.com'],
    'commerce': ['amazon.com', 'ebay.com', 'walmart.com']
}

ALL_TRUSTED_DOMAINS = [d for domains in TRUSTED_DOMAINS.values() for d in domains]
PASSWORD_RESET_PATTERNS = [
    r'password\s+reset', r'reset\s+your\s+password', r'verification\s+code',
    r'security\s+code', r'2fa\s+code'
]
LEGITIMATE_NOREPLY_PATTERNS = ['noreply@', 'no-reply@', 'security@', 'alerts@']
ALL_MARKETING_SERVICES = ['mailchimp.com', 'sendgrid.net', 'constantcontact.com']

def extract_email_metadata(email_text):
    """Extract email metadata"""
    metadata = {}
    try:
        msg = email.message_from_string(email_text)
        metadata['from'] = msg.get('From', '').lower()
        metadata['to'] = msg.get('To', '').lower()
        metadata['subject'] = msg.get('Subject', '')
        metadata['return_path'] = msg.get('Return-Path', '').lower()
        metadata['list_unsubscribe'] = msg.get('List-Unsubscribe', '')
        metadata['spf'] = msg.get('Received-SPF', '')
        metadata['dkim'] = msg.get('DKIM-Signature', '')
    except:
        pass
    return metadata

def detect_legitimate_password_reset(email_text, full_text, metadata):
    """Detect legitimate password reset emails"""
    features = {}
    text_lower = full_text.lower()
    
    reset_count = sum(1 for pattern in PASSWORD_RESET_PATTERNS if re.search(pattern, text_lower))
    features['password_reset_language'] = min(reset_count, 5)
    
    from_trusted = int(any(f'@{d}' in metadata.get('from', '') for d in ALL_TRUSTED_DOMAINS))
    features['reset_from_trusted'] = from_trusted
    
    features['has_security_code'] = int(bool(
        re.search(r'\b\d{4,8}\b', full_text) and 
        any(word in text_lower for word in ['code', 'verification', 'security'])
    ))
    
    features['reset_no_suspicious_urls'] = int(
        features['password_reset_language'] > 0 and
        not re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', full_text)
    )
    
    features['has_expiry_notice'] = int(bool(
        re.search(r'expires?\s+in\s+\d+\s+(hour|minute|day)', text_lower)
    ))
    
    return features

def detect_banking_features(email_text, full_text, metadata):
    """Detect banking features"""
    features = {}
    text_lower = full_text.lower()
    
    from_bank = int(any(f'@{d}' in metadata.get('from', '') for d in TRUSTED_DOMAINS['banking']))
    features['from_banking_domain'] = from_bank
    
    banking_terms = ['account balance', 'transaction', 'statement']
    features['banking_terms_count'] = sum(term in text_lower for term in banking_terms)
    
    features['is_transaction_alert'] = int(bool(
        re.search(r'\$\d+\.\d{2}', full_text) and 'transaction' in text_lower
    ))
    
    features['has_account_reference'] = int(bool(
        re.search(r'account\s+(?:ending|number)?\s*\**\d{4}', text_lower)
    ))
    
    features['legit_security_alert'] = int('security alert' in text_lower or 'fraud alert' in text_lower)
    
    return features

def detect_app_marketing(email_text, full_text, metadata):
    """Detect app marketing"""
    features = {}
    text_lower = full_text.lower()
    
    app_patterns = ['app update', 'download our app', 'app store', 'google play']
    features['app_notification_count'] = sum(pattern in text_lower for pattern in app_patterns)
    
    features['mentions_mobile'] = int(any(word in text_lower for word in ['iphone', 'android', 'ios']))
    features['from_known_app'] = 0
    features['push_notification_style'] = int(bool(
        re.search(r'(new|you have)\s+\d+\s+(message|notification)', text_lower)
    ))
    
    return features

def detect_marketing_legitimacy(email_text, full_text, metadata):
    """Detect marketing legitimacy"""
    features = {}
    text_lower = full_text.lower()
    
    from_marketing = int(any(s in metadata.get('from', '') for s in ALL_MARKETING_SERVICES))
    features['from_marketing_service'] = from_marketing
    
    features['has_proper_unsubscribe'] = int('unsubscribe' in text_lower or 'opt-out' in text_lower)
    features['has_list_unsubscribe_header'] = int(bool(metadata.get('list_unsubscribe')))
    features['has_company_footer'] = int(bool(re.search(r'©\s*\d{4}', full_text)))
    features['has_physical_address'] = int(bool(
        re.search(r'\d+\s+[A-Za-z\s]+(street|st|avenue|ave)', text_lower)
    ))
    
    promo_soft = ['special offer', 'new arrival', 'newsletter']
    features['soft_promotional_count'] = sum(phrase in text_lower for phrase in promo_soft)
    
    spam_aggressive = ['act now', 'limited time', 'expires soon']
    features['aggressive_marketing_count'] = sum(phrase in text_lower for phrase in spam_aggressive)
    
    features['has_view_in_browser'] = int('view in browser' in text_lower)
    features['has_social_links'] = int('follow us' in text_lower or 'connect with us' in text_lower)
    
    return features

def detect_phishing_advanced(email_text, full_text, metadata):
    """Detect phishing"""
    features = {}
    text_lower = full_text.lower()
    
    phishing_urgency = ['suspended', 'locked', 'immediate action', 'within 24 hours']
    features['phishing_urgency_count'] = sum(phrase in text_lower for phrase in phishing_urgency)
    
    account_threats = ['account has been suspended', 'suspicious activity', 'verify immediately']
    features['account_threat_count'] = sum(phrase in text_lower for phrase in account_threats)
    
    credential_requests = ['enter your password', 'confirm your password', 'verify credit card']
    features['requests_credentials'] = sum(phrase in text_lower for phrase in credential_requests)
    
    features['domain_spoof_attempt'] = 0
    if metadata.get('from'):
        spoofed = ['paypa1', 'g00gle', 'micros0ft', 'app1e', 'amaz0n']
        features['domain_spoof_attempt'] = int(any(s in metadata['from'] for s in spoofed))
    
    features['display_name_spoof'] = 0
    
    urls = re.findall(r'http[s]?://[^\s<>"{}|\\^`\[\]]+', full_text)
    features['has_ip_address_url'] = int(any(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) for url in urls))
    
    suspicious_tlds = ['.tk', '.ml', '.ga', '.xyz', '.top']
    features['has_suspicious_tld'] = int(any(any(tld in url for tld in suspicious_tlds) for url in urls))
    
    features['url_shortener'] = int(any(s in url for url in urls for s in ['bit.ly', 'tinyurl']))
    features['many_redirects'] = int(any(url.count('/') > 5 for url in urls))
    
    generic_greetings = ['dear customer', 'dear user', 'valued customer']
    features['generic_greeting'] = int(any(greeting in text_lower for greeting in generic_greetings))
    
    features['excessive_caps'] = int(sum(1 for c in full_text if c.isupper()) / max(len(full_text), 1) > 0.15)
    features['multiple_exclamations'] = int(full_text.count('!') > 5)
    
    return features

def extract_sender_features(metadata):
    """Extract sender features"""
    features = {}
    from_email = metadata.get('from', '')
    
    features['from_trusted_tech'] = int(any(f'@{d}' in from_email for d in TRUSTED_DOMAINS['tech']))
    features['from_trusted_banking'] = int(any(f'@{d}' in from_email for d in TRUSTED_DOMAINS['banking']))
    features['from_trusted_commerce'] = int(any(f'@{d}' in from_email for d in TRUSTED_DOMAINS['commerce']))
    features['legit_noreply'] = int(any(pattern in from_email for pattern in LEGITIMATE_NOREPLY_PATTERNS))
    features['sender_return_mismatch'] = 0
    features['has_spf'] = int(bool(metadata.get('spf')))
    features['has_dkim'] = int(bool(metadata.get('dkim')))
    
    return features

def extract_content_features(full_text):
    """Extract content features"""
    features = {}
    
    urls = re.findall(r'http[s]?://[^\s<>"]+', full_text)
    features['url_count'] = min(len(urls), 20)
    features['has_urls'] = int(len(urls) > 0)
    features['money_mentions'] = len(re.findall(r'[\$£€¥]\s*[\d,]+', full_text))
    features['exclamation_count'] = min(full_text.count('!'), 10)
    features['question_count'] = min(full_text.count('?'), 5)
    features['text_length'] = min(len(full_text), 10000)
    features['word_count'] = len(full_text.split())
    features['html_tags_count'] = min(full_text.count('<'), 100)
    features['is_html_heavy'] = int(full_text.count('<') > 50)
    
    words = full_text.split()
    caps_words = [w for w in words if w.isupper() and len(w) > 2]
    features['caps_words_count'] = min(len(caps_words), 20)
    
    return features

def extract_all_features(email_text):
    """Extract all features"""
    features = {}
    metadata = extract_email_metadata(email_text)
    
    try:
        msg = email.message_from_string(email_text)
        subject = msg.get('Subject', '')
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        body += str(part.get_payload())
        else:
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                body = str(msg.get_payload())
        
        full_text = f"{subject} {body}"
    except:
        full_text = email_text
    
    features.update(extract_sender_features(metadata))
    features.update(detect_legitimate_password_reset(email_text, full_text, metadata))
    features.update(detect_banking_features(email_text, full_text, metadata))
    features.update(detect_app_marketing(email_text, full_text, metadata))
    features.update(detect_marketing_legitimacy(email_text, full_text, metadata))
    features.update(detect_phishing_advanced(email_text, full_text, metadata))
    features.update(extract_content_features(full_text))
    
    return features, full_text

def preprocess_text(text):
    """Preprocess text"""
    if not text:
        return ""
    
    text = text.lower()
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' emailaddress ', text)
    text = re.sub(r'http[s]?://[^\s]+', ' urllink ', text)
    text = re.sub(r'\$\d+(?:\.\d{2})?', ' moneymention ', text)
    text = re.sub(r'\b\d{4,}\b', ' numbercode ', text)
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'[^a-zA-Z0-9\s!?]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

# ============================================
# MODEL LOADING AND PREDICTION
# ============================================

def load_model():
    """Load the trained model"""
    global model, vectorizer, scaler, feature_columns
    
    print(f"Loading trained model from: {MODEL_PATH}")
    
    if not os.path.exists(MODEL_PATH):
        print(f"❌ Error: Model file not found at {MODEL_PATH}")
        print(f"   Current directory: {os.getcwd()}")
        return False
    
    try:
        with open(MODEL_PATH, 'rb') as f:
            saved = pickle.load(f)
        
        model = saved['model']
        vectorizer = saved['vectorizer']
        scaler = saved['scaler']
        feature_columns = saved['feature_columns']
        
        print("✅ Email classifier model loaded successfully!")
        print(f"   Features: {len(feature_columns)}")
        return True
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return False

def classify_email_text(email_text):
    """Classify email"""
    try:
        # Extract features
        features, full_text = extract_all_features(email_text)
        processed = preprocess_text(full_text)
        
        # Vectorize
        text_vec = vectorizer.transform([processed])
        feat_values = [features.get(col, 0) for col in feature_columns]
        feat_scaled = scaler.transform(csr_matrix([feat_values]))
        combined = hstack([text_vec, feat_scaled])
        
        # Predict
        prediction = model.predict(combined)[0]
        probabilities = model.predict_proba(combined)[0]
        
        verdict_map = {0: 'ham', 1: 'spam', 2: 'phishing'}
        class_names = ['Legitimate', 'Spam/Marketing', 'Phishing']
        
        verdict = verdict_map[prediction]
        confidence = float(probabilities[prediction])
        detailed_result = class_names[prediction]
        
        # Generate explanation
        explanation = []
        if prediction == 0:
            if features.get('from_trusted_tech', 0):
                explanation.append("From trusted technology company")
            if features.get('password_reset_language', 0) > 0:
                explanation.append("Legitimate password reset email")
            if not explanation:
                explanation.append("No suspicious indicators found")
        elif prediction == 1:
            if features.get('has_proper_unsubscribe', 0):
                explanation.append("Contains unsubscribe link")
            if features.get('from_marketing_service', 0):
                explanation.append("Sent via email marketing service")
            if not explanation:
                explanation.append("Marketing/promotional email")
        else:
            if features.get('phishing_urgency_count', 0) > 0:
                explanation.append("Uses threatening urgency tactics")
            if features.get('has_ip_address_url', 0):
                explanation.append("URL contains IP address")
            if not explanation:
                explanation.append("Suspicious phishing indicators detected")
        
        return {
            'verdict': verdict,
            'confidence': confidence,
            'classification': detailed_result,
            'probabilities': {
                'legitimate': float(probabilities[0]),
                'spam': float(probabilities[1]),
                'phishing': float(probabilities[2])
            },
            'explanation': explanation
        }
        
    except Exception as e:
        print(f"Error during classification: {e}")
        import traceback
        traceback.print_exc()
        return {
            'verdict': 'unknown',
            'confidence': 0.0,
            'classification': 'Unknown',
            'probabilities': {'legitimate': 0.0, 'spam': 0.0, 'phishing': 0.0},
            'explanation': [f'Error: {str(e)}']
        }

# ============================================
# FLASK ROUTES
# ============================================

@app.route("/predict", methods=["POST"])
def predict():
    """Endpoint to classify email"""
    if model is None:
        return jsonify({"error": "Model not loaded"}), 500
    
    if not request.json or 'text' not in request.json:
        return jsonify({"error": "Missing 'text' field in request"}), 400
    
    email_text = request.json.get('text', '').strip()
    
    if not email_text:
        return jsonify({
            "verdict": "ham",
            "confidence": 1.0,
            "classification": "Legitimate",
            "probabilities": {"legitimate": 1.0, "spam": 0.0, "phishing": 0.0},
            "explanation": ["Empty email"]
        }), 200
    
    try:
        result = classify_email_text(email_text)
        print(f"📧 Classified as: {result['classification']} ({result['confidence']*100:.1f}%)")
        return jsonify(result), 200
    except Exception as e:
        print(f"Error in prediction endpoint: {e}")
        return jsonify({"error": "Failed to classify email"}), 500

@app.route("/health", methods=["GET"])
def health():
    """Health check"""
    return jsonify({
        "status": "healthy",
        "model_loaded": model is not None
    }), 200

@app.route("/info", methods=["GET"])
def info():
    """Model info"""
    if model is None:
        return jsonify({"error": "Model not loaded"}), 500
    
    return jsonify({
        "model_name": "Enhanced Email Classifier",
        "version": "1.0",
        "classes": {"0": "Legitimate (ham)", "1": "Spam (spam)", "2": "Phishing (phishing)"},
        "features": len(feature_columns) if feature_columns else 0
    }), 200

@app.route("/", methods=["GET"])
def root():
    """Root endpoint"""
    return jsonify({
        "service": "Email Classifier API",
        "status": "running",
        "model_loaded": model is not None
    }), 200

# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    print("\n" + "="*60)
    print("EMAIL CLASSIFIER API SERVER")
    print("="*60)
    print(f"Working directory: {os.getcwd()}")
    print(f"Looking for model: {MODEL_PATH}")
    print("="*60 + "\n")
    
    if load_model():
        print("\n✅ Server ready!")
        print("\nEndpoints:")
        print("  POST /predict")
        print("  GET  /health")
        print("  GET  /info")
        print("\n🚀 Starting Flask server on http://localhost:5001\n")
        app.run(host="0.0.0.0", port=5001, debug=False)
    else:
        print("\n❌ Failed to load model. Train it first:")
        print("  python train_phishing_model.py\n")