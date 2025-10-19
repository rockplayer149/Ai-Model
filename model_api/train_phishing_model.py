import pandas as pd
import numpy as np
import re
import email
from email import policy
from email.parser import BytesParser, Parser
import os
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
import pickle
from scipy.sparse import hstack, csr_matrix
import warnings
warnings.filterwarnings('ignore')

# ============================================
# EXPANDED TRUSTED DOMAINS AND PATTERNS
# ============================================

TRUSTED_DOMAINS = {
    'tech': ['google.com', 'gmail.com', 'gstatic.com', 'googleapis.com',
             'microsoft.com', 'outlook.com', 'live.com', 'office.com',
             'apple.com', 'icloud.com', 'me.com', 'github.com', 'gitlab.com'],
    
    'banking': ['bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citi.com',
                'capitalone.com', 'usbank.com', 'pnc.com', 'ally.com',
                'discover.com', 'americanexpress.com', 'paypal.com', 'stripe.com',
                'square.com', 'venmo.com', 'cashapp.com'],
    
    'commerce': ['amazon.com', 'amazonaws.com', 'ebay.com', 'etsy.com',
                 'walmart.com', 'target.com', 'bestbuy.com', 'shopify.com'],
    
    'social': ['facebook.com', 'meta.com', 'instagram.com', 'twitter.com', 
               'x.com', 'linkedin.com', 'reddit.com', 'tiktok.com', 'snapchat.com'],
    
    'services': ['dropbox.com', 'box.com', 'slack.com', 'zoom.us', 'discord.com',
                 'notion.so', 'trello.com', 'asana.com', 'monday.com']
}

ALL_TRUSTED_DOMAINS = [d for domains in TRUSTED_DOMAINS.values() for d in domains]

PASSWORD_RESET_PATTERNS = [
    r'password\s+reset',
    r'reset\s+your\s+password',
    r'forgot\s+your\s+password',
    r'password\s+recovery',
    r'security\s+code',
    r'verification\s+code',
    r'two-factor\s+authentication',
    r'2fa\s+code',
    r'confirm\s+your\s+email',
    r'verify\s+your\s+email\s+address'
]

LEGITIMATE_NOREPLY_PATTERNS = [
    'noreply@', 'no-reply@', 'donotreply@', 'notifications@',
    'security@', 'alerts@', 'updates@', 'support@', 'help@'
]

MARKETING_SERVICES = {
    'email_services': ['mailchimp.com', 'sendgrid.net', 'mailgun.com', 
                      'postmarkapp.com', 'mailjet.com', 'sendinblue.com',
                      'constantcontact.com', 'awsmail.com', 'amazonses.com',
                      'sparkpostmail.com', 'mandrillapp.com'],
    
    'marketing_platforms': ['hubspot.com', 'marketo.com', 'pardot.com',
                           'eloqua.com', 'mcsv.net', 'campaign-monitor.com',
                           'getresponse.com', 'activecampaign.com']
}

ALL_MARKETING_SERVICES = [d for services in MARKETING_SERVICES.values() for d in services]

# ============================================
# FEATURE EXTRACTION FUNCTIONS
# ============================================

def extract_email_metadata(email_text):
    """Extract detailed email metadata"""
    metadata = {}
    
    try:
        msg = email.message_from_string(email_text)
        
        metadata['from'] = msg.get('From', '').lower()
        metadata['to'] = msg.get('To', '').lower()
        metadata['subject'] = msg.get('Subject', '')
        metadata['return_path'] = msg.get('Return-Path', '').lower()
        metadata['reply_to'] = msg.get('Reply-To', '').lower()
        metadata['message_id'] = msg.get('Message-ID', '')
        
        metadata['spf'] = msg.get('Received-SPF', '')
        metadata['dkim'] = msg.get('DKIM-Signature', '')
        metadata['dmarc'] = msg.get('Authentication-Results', '')
        
        metadata['list_unsubscribe'] = msg.get('List-Unsubscribe', '')
        metadata['precedence'] = msg.get('Precedence', '')
        
    except:
        pass
    
    return metadata

def detect_legitimate_password_reset(email_text, full_text, metadata):
    """Detect legitimate password reset emails"""
    features = {}
    text_lower = full_text.lower()
    
    reset_count = sum(1 for pattern in PASSWORD_RESET_PATTERNS 
                     if re.search(pattern, text_lower))
    features['password_reset_language'] = min(reset_count, 5)
    
    from_trusted = 0
    for domain in ALL_TRUSTED_DOMAINS:
        if f'@{domain}' in metadata.get('from', ''):
            from_trusted = 1
            break
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
        re.search(r'expires?\s+in\s+\d+\s+(hour|minute|day)', text_lower) or
        re.search(r'valid\s+for\s+\d+\s+(hour|minute|day)', text_lower)
    ))
    
    return features

def detect_banking_features(email_text, full_text, metadata):
    """Detect legitimate banking email features"""
    features = {}
    text_lower = full_text.lower()
    
    from_bank = 0
    for domain in TRUSTED_DOMAINS['banking']:
        if f'@{domain}' in metadata.get('from', ''):
            from_bank = 1
            break
    features['from_banking_domain'] = from_bank
    
    banking_terms = ['account balance', 'transaction', 'statement', 
                    'direct deposit', 'wire transfer', 'ach', 
                    'routing number', 'account ending in']
    features['banking_terms_count'] = sum(term in text_lower for term in banking_terms)
    
    features['is_transaction_alert'] = int(bool(
        re.search(r'\$\d+\.\d{2}', full_text) and
        any(word in text_lower for word in ['charged', 'transaction', 'purchase', 'withdrawal'])
    ))
    
    features['has_account_reference'] = int(bool(
        re.search(r'account\s+(?:ending|number)?\s*(?:in|#)?\s*\**\d{4}', text_lower)
    ))
    
    security_alert_legit = ['we noticed', 'detected unusual', 'for your security',
                           'security alert', 'fraud alert']
    features['legit_security_alert'] = int(any(phrase in text_lower for phrase in security_alert_legit))
    
    return features

def detect_app_marketing(email_text, full_text, metadata):
    """Detect legitimate app marketing/notifications"""
    features = {}
    text_lower = full_text.lower()
    
    app_patterns = ['new feature', 'app update', 'version', 'download our app',
                   'available on', 'app store', 'google play', 'get the app']
    features['app_notification_count'] = sum(pattern in text_lower for pattern in app_patterns)
    
    features['mentions_mobile'] = int(any(word in text_lower for word in 
        ['iphone', 'android', 'ios', 'mobile app', 'smartphone']))
    
    app_companies = ['uber', 'lyft', 'doordash', 'grubhub', 'spotify', 
                    'netflix', 'hulu', 'disney', 'airbnb', 'booking']
    features['from_known_app'] = 0
    for company in app_companies:
        if company in metadata.get('from', ''):
            features['from_known_app'] = 1
            break
    
    features['push_notification_style'] = int(bool(
        re.search(r'(new|you have)\s+\d+\s+(message|notification|update|alert)', text_lower)
    ))
    
    return features

def detect_marketing_legitimacy(email_text, full_text, metadata):
    """Enhanced marketing email detection"""
    features = {}
    text_lower = full_text.lower()
    
    from_marketing = 0
    for service in ALL_MARKETING_SERVICES:
        if service in metadata.get('from', '') or service in metadata.get('return_path', ''):
            from_marketing = 1
            break
    features['from_marketing_service'] = from_marketing
    
    unsubscribe_patterns = [
        r'unsubscribe',
        r'opt-out',
        r'manage\s+(?:email\s+)?preferences',
        r'update\s+(?:email\s+)?preferences'
    ]
    features['has_proper_unsubscribe'] = int(any(
        re.search(pattern, text_lower) for pattern in unsubscribe_patterns
    ))
    
    features['has_list_unsubscribe_header'] = int(bool(metadata.get('list_unsubscribe')))
    
    features['has_company_footer'] = int(bool(
        re.search(r'(©|copyright)\s+\d{4}', full_text) or
        re.search(r'all\s+rights\s+reserved', text_lower)
    ))
    
    features['has_physical_address'] = int(bool(
        re.search(r'\d+\s+[A-Za-z\s]+(?:street|st|avenue|ave|road|rd|drive|dr|boulevard|blvd)', text_lower)
    ))
    
    promo_soft = ['special offer', 'new arrival', 'just launched', 'announcement',
                 'update', 'newsletter', 'this week', 'monthly']
    features['soft_promotional_count'] = sum(phrase in text_lower for phrase in promo_soft)
    
    spam_aggressive = ['act now', 'limited time', 'expires soon', 'don\'t miss',
                      'hurry', 'urgent', 'last chance', 'only today']
    features['aggressive_marketing_count'] = sum(phrase in text_lower for phrase in spam_aggressive)
    
    features['has_view_in_browser'] = int('view in browser' in text_lower or 'view online' in text_lower)
    features['has_social_links'] = int(bool(
        re.search(r'(follow us|connect with us|find us on)', text_lower)
    ))
    
    return features

def detect_phishing_advanced(email_text, full_text, metadata):
    """Advanced phishing detection"""
    features = {}
    text_lower = full_text.lower()
    
    phishing_urgency = [
        'suspended', 'locked', 'closed', 'terminated',
        'immediate action', 'act immediately', 'within 24 hours',
        'expire today', 'expires in', 'limited time to',
        'click now or', 'respond now or'
    ]
    features['phishing_urgency_count'] = sum(phrase in text_lower for phrase in phishing_urgency)
    
    account_threats = [
        'account has been suspended',
        'account will be closed',
        'unauthorized access detected',
        'suspicious activity',
        'unusual login attempt',
        'verify immediately',
        'confirm your identity'
    ]
    features['account_threat_count'] = sum(phrase in text_lower for phrase in account_threats)
    
    credential_requests = [
        'enter your password',
        'confirm your password',
        'update payment information',
        'verify credit card',
        'social security number',
        'update billing',
        'confirm account details'
    ]
    features['requests_credentials'] = sum(phrase in text_lower for phrase in credential_requests)
    
    features['domain_spoof_attempt'] = 0
    if metadata.get('from'):
        from_email = metadata['from']
        
        spoofed_brands = {
            'paypal': ['paypa1', 'paypai', 'paypa-'],
            'google': ['g00gle', 'gooogle', 'googie'],
            'microsoft': ['micros0ft', 'microssoft', 'microsoft-'],
            'apple': ['app1e', 'appie', 'apple-'],
            'amazon': ['amaz0n', 'amazone', 'amazon-']
        }
        
        for brand, variants in spoofed_brands.items():
            if any(variant in from_email for variant in variants):
                features['domain_spoof_attempt'] = 1
                break
    
    features['display_name_spoof'] = 0
    if metadata.get('from') and '<' in metadata['from']:
        display_name = metadata['from'].split('<')[0].strip().lower()
        email_part = metadata['from'].split('<')[1].split('>')[0].lower()
        
        trusted_brands = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 
                         'bank', 'wells fargo', 'chase', 'citibank']
        
        for brand in trusted_brands:
            if brand in display_name:
                if not any(domain in email_part for domain in ALL_TRUSTED_DOMAINS):
                    features['display_name_spoof'] = 1
                    break
    
    urls = re.findall(r'http[s]?://[^\s<>"{}|\\^`\[\]]+', full_text)
    features['has_ip_address_url'] = 0
    features['has_suspicious_tld'] = 0
    features['url_shortener'] = 0
    features['many_redirects'] = 0
    
    if urls:
        for url in urls:
            url_lower = url.lower()
            
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                features['has_ip_address_url'] = 1
            
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', 
                             '.pw', '.cc', '.info', '.biz']
            if any(tld in url_lower for tld in suspicious_tlds):
                features['has_suspicious_tld'] = 1
            
            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
            if any(short in url_lower for short in shorteners):
                features['url_shortener'] = 1
            
            if url.count('/') > 5 or '@' in url:
                features['many_redirects'] = 1
    
    generic_greetings = [
        'dear customer', 'dear user', 'dear member',
        'valued customer', 'dear sir/madam', 'hello user',
        'dear account holder', 'greetings'
    ]
    features['generic_greeting'] = int(any(greeting in text_lower for greeting in generic_greetings))
    
    features['excessive_caps'] = int(sum(1 for c in full_text if c.isupper()) / max(len(full_text), 1) > 0.15)
    features['multiple_exclamations'] = int(full_text.count('!!') > 0 or full_text.count('!') > 5)
    
    return features

def extract_sender_features(metadata):
    """Extract sender-related features"""
    features = {}
    
    from_email = metadata.get('from', '')
    
    features['from_trusted_tech'] = int(any(f'@{d}' in from_email for d in TRUSTED_DOMAINS['tech']))
    features['from_trusted_banking'] = int(any(f'@{d}' in from_email for d in TRUSTED_DOMAINS['banking']))
    features['from_trusted_commerce'] = int(any(f'@{d}' in from_email for d in TRUSTED_DOMAINS['commerce']))
    
    features['legit_noreply'] = int(any(pattern in from_email for pattern in LEGITIMATE_NOREPLY_PATTERNS))
    
    features['sender_return_mismatch'] = 0
    if metadata.get('from') and metadata.get('return_path'):
        from_domain = from_email.split('@')[-1] if '@' in from_email else ''
        return_domain = metadata['return_path'].split('@')[-1] if '@' in metadata['return_path'] else ''
        
        if from_domain and return_domain and from_domain != return_domain:
            if not any(service in from_domain or service in return_domain 
                      for service in ALL_MARKETING_SERVICES):
                features['sender_return_mismatch'] = 1
    
    features['has_spf'] = int(bool(metadata.get('spf')))
    features['has_dkim'] = int(bool(metadata.get('dkim')))
    
    return features

def extract_content_features(full_text):
    """Extract content-based features"""
    features = {}
    text_lower = full_text.lower()
    
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
    """Extract all features comprehensively"""
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
    """Enhanced text preprocessing"""
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
# DATA LOADING
# ============================================

def load_phishing_emails(phishing_dir, max_emails=None):
    """Load phishing emails"""
    emails = []
    labels = []
    
    print("\n[Loading Phishing Emails]")
    
    if not os.path.exists(phishing_dir):
        print(f"   ✗ Directory not found: {phishing_dir}")
        return [], []
    
    files = [f for f in os.listdir(phishing_dir) if os.path.isfile(os.path.join(phishing_dir, f))]
    
    for filename in files:
        if max_emails and len(emails) >= max_emails:
            break
        
        filepath = os.path.join(phishing_dir, filename)
        
        try:
            for encoding in ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']:
                try:
                    with open(filepath, 'r', encoding=encoding) as f:
                        text = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if text and len(text) > 50:
                emails.append(text)
                labels.append(2)
                
                if len(emails) % 100 == 0:
                    print(f"   → Loaded {len(emails)} phishing emails...")
        except:
            continue
    
    print(f"   ✓ Total phishing emails: {len(emails)}")
    return emails, labels

def create_diverse_spam_samples(spam_dir, num_samples=600):
    """Create diverse spam/marketing email samples"""
    os.makedirs(spam_dir, exist_ok=True)
    
    print("\n[Creating Spam/Marketing Samples]")
    
    templates = {
        'retail_marketing': [
            """Subject: {discount}% OFF - {event}!
From: deals@{company}.com
List-Unsubscribe: <mailto:unsubscribe@{company}.com>

Dear Valued Subscriber,

{event_desc}

✓ {discount}% OFF everything
✓ Free shipping on orders over $50
✓ Exclusive member benefits

Shop Now: http://deals.{company}.com/sale

This offer is valid for 48 hours only!

Unsubscribe | Manage Preferences | View in Browser

{company} Marketing Team
123 Main Street, City, ST 12345
© 2024 {company}. All rights reserved."""
        ],
        
        'newsletter': [
            """Subject: Your Weekly {topic} Newsletter
From: newsletter@{company}.com
List-Unsubscribe: <mailto:unsubscribe@{company}.com>
Precedence: bulk

Hi there,

Here's what's trending this week in {topic}:

• Top story of the week
• Industry insights and analysis
• Upcoming events you won't want to miss
• Expert tips and tricks

Read more: http://{company}.com/newsletter

Follow us on social media for daily updates!

Unsubscribe | Update email preferences

{company} Team
View in browser

{company} Inc.
789 Business Ave, San Francisco, CA 94105"""
        ],
        
        'app_promotion': [
            """Subject: Get {app_name} - {benefit}!
From: team@{app_name}.com
List-Unsubscribe: <mailto:unsubscribe@{app_name}.com>

Hello,

Download {app_name} and start enjoying {benefit} today!

📱 Available on iOS and Android
⭐ Rated 4.8/5 by over 1M users
🎉 Sign up bonus: {bonus}

Download now: http://{app_name}.com/download

Get the app:
• App Store
• Google Play

Questions? Contact support@{app_name}.com

Unsubscribe from promotional emails

{app_name} Team
456 Tech Blvd, Austin, TX 78701
© 2024 {app_name}. All rights reserved."""
        ],
        
        'promotional': [
            """Subject: Limited Time Offer - Save Big!
From: offers@marketing.{company}.com
List-Unsubscribe: <mailto:unsubscribe@{company}.com>

Hi,

Don't miss our special promotion this weekend!

🎁 {discount}% off sitewide
🚚 Free shipping 
💳 Easy returns

Shop now: https://{company}.com/offers

This offer expires soon. Terms and conditions apply.

Unsubscribe | Privacy Policy

{company} Marketing
© 2024 {company} Inc. All rights reserved.
321 Commerce St, New York, NY 10001"""
        ],
        
        'aggressive_spam': [
            """Subject: ACT NOW!!! URGENT - Limited Time!!!
From: offers@deals-today.xyz

CONGRATULATIONS!!!

You have been selected for an EXCLUSIVE opportunity!!!

🎁 $1000 CASH PRIZE 🎁
🎯 100% FREE
⚡ ACT NOW - EXPIRES IN 24 HOURS!!!

Click here immediately: http://bit.ly/xyz123

DON'T MISS THIS AMAZING OPPORTUNITY!!!

This is a LIMITED TIME offer!!! Hurry!!!"""
        ],
        
        'suspicious_marketing': [
            """Subject: URGENT: Claim Your Prize NOW!!!
From: winner@prizecentral.info

You WON $5000!!!

Click here NOW to claim: http://prize-claim.tk/winner

HURRY! Offer expires TODAY!

Limited time only! ACT FAST!!!"""
        ]
    }
    
    emails = []
    
    samples_per_category = {
        'retail_marketing': int(num_samples * 0.30),
        'newsletter': int(num_samples * 0.25),
        'app_promotion': int(num_samples * 0.20),
        'promotional': int(num_samples * 0.15),
        'aggressive_spam': int(num_samples * 0.05),
        'suspicious_marketing': int(num_samples * 0.05)
    }
    
    for category, template_list in templates.items():
        samples_needed = samples_per_category.get(category, 0)
        
        for template in template_list:
            samples_per_template = samples_needed // len(template_list)
            
            for i in range(samples_per_template):
                email_text = template.format(
                    discount=np.random.choice([15, 20, 25, 30, 40, 50, 70]),
                    event=np.random.choice(['Flash Sale', 'Weekend Special', 'Holiday Sale', 
                                           'Clearance', 'Spring Sale', 'Member Exclusive']),
                    event_desc=np.random.choice([
                        'Our biggest sale of the year!', 
                        'Don\'t miss these amazing deals!',
                        'Exclusive offers just for you!',
                        'Special savings for our valued customers!'
                    ]),
                    company=np.random.choice(['TechStore', 'FashionHub', 'HomeGoods', 
                                            'SportsPro', 'ElectroMart', 'StyleShop']),
                    topic=np.random.choice(['Technology', 'Business', 'Marketing', 'Design', 
                                          'Science', 'Finance']),
                    app_name=np.random.choice(['TaskMaster', 'FitPro', 'PhotoEdit', 
                                              'MusicStream', 'StudyBuddy', 'TravelPlanner']),
                    benefit=np.random.choice(['amazing features', 'unlimited access', 
                                            'premium content', 'exclusive tools']),
                    bonus=np.random.choice(['$10 credit', '1 month free', '50% off first order',
                                          '100 bonus points'])
                )
                
                filename = f"{category}_{i:04d}.txt"
                filepath = os.path.join(spam_dir, filename)
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(email_text)
                
                emails.append(email_text)
    
    print(f"   ✓ Created {len(emails)} spam/marketing samples")
    return emails, [1] * len(emails)

def create_password_reset_samples(reset_dir, num_samples=200):
    """Create legitimate password reset email samples"""
    os.makedirs(reset_dir, exist_ok=True)
    
    print("\n[Creating Password Reset Samples]")
    
    templates = [
        """Subject: Password Reset Request
From: security-noreply@google.com

Hello,

You recently requested to reset your password for your Google Account.

Your verification code is: {code}

This code will expire in 10 minutes.

If you didn't request this, you can safely ignore this email.

Thanks,
The Google Accounts team""",

        """Subject: Reset your Apple ID password
From: appleid@id.apple.com

Hi,

A password reset was requested for your Apple ID.

To reset your password, click here: https://iforgot.apple.com/password/verify/appleid

Security Code: {code}

This link will expire in 3 hours.

If you didn't make this request, contact Apple Support immediately.

Apple ID Support""",

        """Subject: Password Reset - Microsoft Account
From: account-security-noreply@accountprotection.microsoft.com

Hello,

We received a request to reset your Microsoft account password.

Security Code: {code}

Use this code to complete your password reset. This code expires in 15 minutes.

If you didn't request this change, please secure your account immediately.

Microsoft Account Team""",

        """Subject: Verify Your Email Address
From: no-reply@accounts.github.com

Hi there,

Please verify your email address by clicking the link below:

https://github.com/verify/token

Verification Code: {code}

This link expires in 24 hours.

If you didn't sign up for GitHub, please ignore this email.

Happy coding,
GitHub""",

        """Subject: Two-Factor Authentication Code
From: noreply@linkedin.com

Your LinkedIn verification code is: {code}

This code will expire in 10 minutes.

For your security, don't share this code with anyone.

The LinkedIn Team"""
    ]
    
    emails = []
    
    for i, template in enumerate(templates):
        for j in range(num_samples // len(templates)):
            code = np.random.randint(100000, 999999)
            email_text = template.format(code=code)
            
            filename = f"password_reset_{i}_{j:03d}.txt"
            filepath = os.path.join(reset_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(email_text)
            
            emails.append(email_text)
    
    print(f"   ✓ Created {len(emails)} password reset samples")
    return emails, [0] * len(emails)

def create_banking_samples(banking_dir, num_samples=200):
    """Create legitimate banking email samples"""
    os.makedirs(banking_dir, exist_ok=True)
    
    print("\n[Creating Banking Email Samples]")
    
    templates = [
        """Subject: Transaction Alert - Your Account
From: alerts@chase.com

Dear Customer,

A transaction was processed on your Chase checking account ending in **{account}.

Amount: ${amount:.2f}
Merchant: {merchant}
Date: January 15, 2024

Your current balance is ${balance:.2f}

If you don't recognize this transaction, please contact us immediately at 1-800-935-9935.

For your security, we monitor your account 24/7.

Chase Bank
Member FDIC""",

        """Subject: Monthly Statement Available
From: statements@wellsfargo.com

Hello,

Your Wells Fargo monthly statement for account ***{account} is now available.

Statement Period: December 1-31, 2023
Account Type: Checking

View your statement: https://wellsfargo.com/statements

For questions, call us at 1-800-869-3557.

Wells Fargo Bank
Member FDIC""",

        """Subject: Direct Deposit Notification
From: notifications@bankofamerica.com

Good news!

A direct deposit of ${amount:.2f} has been credited to your Bank of America account ending in **{account}.

Available Balance: ${balance:.2f}

Log in to view details: https://bankofamerica.com

Thank you for banking with us.

Bank of America
Member FDIC""",

        """Subject: Security Alert - New Device Login
From: security@paypal.com

Hi,

We noticed a login to your PayPal account from a new device.

Device: iPhone 12
Location: New York, NY
Time: January 15, 2024 at 2:34 PM EST

Was this you?
Yes, it was me: https://paypal.com/confirm
No, it wasn't me: https://paypal.com/security

For your security, we recommend enabling two-factor authentication.

PayPal Security Team"""
    ]
    
    emails = []
    merchants = ['Amazon.com', 'Starbucks', 'Target', 'Walmart', 'Shell Gas', 'CVS Pharmacy']
    
    for i, template in enumerate(templates):
        for j in range(num_samples // len(templates)):
            amount = np.random.uniform(20, 500)
            balance = np.random.uniform(1000, 5000)
            account = np.random.randint(1000, 9999)
            merchant = np.random.choice(merchants)
            
            email_text = template.format(
                amount=amount,
                balance=balance,
                account=account,
                merchant=merchant
            )
            
            filename = f"banking_{i}_{j:03d}.txt"
            filepath = os.path.join(banking_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(email_text)
            
            emails.append(email_text)
    
    print(f"   ✓ Created {len(emails)} banking samples")
    return emails, [0] * len(emails)

def load_legitimate_emails(csv_path, max_emails=None):
    """Load legitimate emails from Enron dataset"""
    emails = []
    labels = []
    
    print("\n[Loading Legitimate Emails from Enron Dataset]")
    
    try:
        df = None
        for encoding in ['utf-8', 'latin-1', 'iso-8859-1']:
            try:
                df = pd.read_csv(csv_path, encoding=encoding)
                break
            except:
                continue
        
        if df is None:
            return [], []
        
        text_col = None
        for col in ['message', 'text', 'body', 'content', 'email']:
            if col in df.columns:
                text_col = col
                break
        
        if text_col is None:
            text_col = df.columns[0]
        
        count = 0
        for idx, row in df.iterrows():
            if max_emails and count >= max_emails:
                break
            
            try:
                text = str(row[text_col])
                if text and len(text) > 100 and text.lower() not in ['nan', 'none']:
                    text_lower = text.lower()
                    spam_indicators = ['unsubscribe', 'click here now', '100% free', 'limited time offer']
                    
                    if not any(indicator in text_lower for indicator in spam_indicators):
                        emails.append(text)
                        labels.append(0)
                        count += 1
                        
                        if count % 500 == 0:
                            print(f"   → Loaded {count} legitimate emails...")
            except:
                continue
        
        print(f"   ✓ Total legitimate emails: {len(emails)}")
        return emails, labels
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return [], []

# ============================================
# TRAINING
# ============================================

def train_enhanced_classifier(phishing_dir, csv_path, output_model='enhanced_email_classifier.pkl'):
    """Train enhanced 3-class classifier with better accuracy"""
    
    print("\n" + "="*70)
    print("ENHANCED 3-CLASS EMAIL CLASSIFIER")
    print("Classes: Legitimate (0) | Spam/Marketing (1) | Phishing (2)")
    print("="*70)
    
    print("\n📁 Loading datasets...")
    
    phishing_emails, phishing_labels = load_phishing_emails(phishing_dir, max_emails=600)
    spam_emails, spam_labels = create_diverse_spam_samples('../datasets/spam', num_samples=600)
    reset_emails, reset_labels = create_password_reset_samples('../datasets/password_reset', num_samples=200)
    banking_emails, banking_labels = create_banking_samples('../datasets/banking', num_samples=200)
    legit_emails, legit_labels = load_legitimate_emails(csv_path, max_emails=1200)
    
    all_legit_emails = legit_emails + reset_emails + banking_emails
    all_legit_labels = legit_labels + reset_labels + banking_labels
    
    all_emails = all_legit_emails + spam_emails + phishing_emails
    all_labels = all_legit_labels + spam_labels + phishing_labels
    
    print(f"\n📊 Dataset Summary:")
    print(f"   Legitimate: {all_labels.count(0)} (including {len(reset_emails)} password resets, {len(banking_emails)} banking)")
    print(f"   Spam:       {all_labels.count(1)}")
    print(f"   Phishing:   {all_labels.count(2)}")
    print(f"   Total:      {len(all_labels)}")
    
    print("\n🔬 Extracting features...")
    feature_dicts = []
    processed_texts = []
    
    for i, email_text in enumerate(all_emails):
        try:
            features, full_text = extract_all_features(email_text)
            feature_dicts.append(features)
            processed_texts.append(preprocess_text(full_text))
            
            if (i + 1) % 300 == 0:
                print(f"   → Processed {i + 1}/{len(all_emails)}")
        except Exception as e:
            feature_dicts.append({})
            processed_texts.append("")
    
    feature_df = pd.DataFrame(feature_dicts).fillna(0)
    
    print(f"\n   ✓ Extracted {len(feature_df.columns)} features")
    
    print("\n✂️  Splitting data (80/20 train/test)...")
    X_train_text, X_test_text, X_train_feat, X_test_feat, y_train, y_test = train_test_split(
        processed_texts, feature_df.values, all_labels,
        test_size=0.2, random_state=42, stratify=all_labels
    )
    
    print(f"   Training samples: {len(y_train)}")
    print(f"   Test samples: {len(y_test)}")
    
    print("\n🔢 Vectorizing text with TF-IDF...")
    vectorizer = TfidfVectorizer(
        max_features=3500,
        ngram_range=(1, 3),
        min_df=3,
        max_df=0.80,
        sublinear_tf=True,
        strip_accents='unicode',
        analyzer='word',
        token_pattern=r'\w{1,}',
        use_idf=True,
        smooth_idf=True
    )
    
    X_train_vec = vectorizer.fit_transform(X_train_text)
    X_test_vec = vectorizer.transform(X_test_text)
    
    print(f"   Text features: {X_train_vec.shape[1]}")
    
    scaler = StandardScaler(with_mean=False)
    X_train_feat_scaled = scaler.fit_transform(csr_matrix(X_train_feat))
    X_test_feat_scaled = scaler.transform(csr_matrix(X_test_feat))
    
    X_train_combined = hstack([X_train_vec, X_train_feat_scaled])
    X_test_combined = hstack([X_test_vec, X_test_feat_scaled])
    
    print(f"   Total features: {X_train_combined.shape[1]}")
    
    print("\n🧠 Training ensemble model...")
    
    classes = np.unique(y_train)
    class_weights = compute_class_weight('balanced', classes=classes, y=y_train)
    class_weight_dict = {i: class_weights[i] for i in range(len(classes))}
    class_weight_dict[2] = class_weight_dict[2] * 1.5
    
    lr = LogisticRegression(
        max_iter=2000,
        C=1.5,
        random_state=42,
        multi_class='multinomial',
        class_weight=class_weight_dict,
        solver='lbfgs'
    )
    
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=35,
        min_samples_split=3,
        min_samples_leaf=1,
        random_state=42,
        class_weight=class_weight_dict,
        n_jobs=-1,
        max_features='sqrt'
    )
    
    gb = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.08,
        max_depth=8,
        min_samples_split=4,
        random_state=42,
        subsample=0.9
    )
    
    ensemble = VotingClassifier(
        estimators=[
            ('lr', lr),
            ('rf', rf),
            ('gb', gb)
        ],
        voting='soft',
        weights=[3, 2, 1]
    )
    
    ensemble.fit(X_train_combined, y_train)
    
    print("\n📈 Evaluating model...")
    y_pred = ensemble.predict(X_test_combined)
    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='weighted')
    
    print(f"\n   Overall Accuracy: {accuracy:.4f}")
    print(f"   Weighted F1-Score: {f1:.4f}")
    
    print(f"\n{classification_report(y_test, y_pred, target_names=['Legitimate', 'Spam/Marketing', 'Phishing'])}")
    
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print("                  Predicted")
    print("                  Legit  Spam  Phish")
    print(f"Actual Legit    : {cm[0][0]:5d} {cm[0][1]:5d} {cm[0][2]:5d}")
    print(f"       Spam     : {cm[1][0]:5d} {cm[1][1]:5d} {cm[1][2]:5d}")
    print(f"       Phishing : {cm[2][0]:5d} {cm[2][1]:5d} {cm[2][2]:5d}")
    
    print(f"\n💾 Saving model...")
    model_data = {
        'model': ensemble,
        'vectorizer': vectorizer,
        'scaler': scaler,
        'feature_columns': list(feature_df.columns)
    }
    
    with open(output_model, 'wb') as f:
        pickle.dump(model_data, f)
    
    print(f"   ✓ Model saved to {output_model}")
    
    return ensemble, vectorizer, scaler, feature_df.columns

# ============================================
# MAIN
# ============================================

def main():
    CSV_PATH = "../datasets/emails.csv"
    PHISHING_DIR = "../datasets/phishing"
    
    if not os.path.exists(CSV_PATH):
        print(f"❌ Missing: {CSV_PATH}")
        print("   Download from: https://www.kaggle.com/datasets/wcukierski/enron-email-dataset")
        return
    
    if not os.path.exists(PHISHING_DIR):
        print(f"❌ Missing: {PHISHING_DIR}")
        print("   Download from: https://monkey.org/~jose/phishing/")
        return
    
    print("\n🚀 Starting training...")
    model, vectorizer, scaler, features = train_enhanced_classifier(
        PHISHING_DIR, 
        CSV_PATH,
        output_model='enhanced_email_classifier.pkl'
    )
    
    print("\n" + "="*70)
    print("✅ Training complete!")
    print("="*70)
    print("\nModel saved: enhanced_email_classifier.pkl")
    print("\nNext steps:")
    print("  1. Test the model: python test_email_classifier.py")
    print("  2. Start the API: python app.py")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()