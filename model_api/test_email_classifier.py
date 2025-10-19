import pandas as pd
import numpy as np
import pickle
import os
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

# Import the enhanced classifier functions
from train_phishing_model import (
    extract_all_features, 
    preprocess_text,
    load_phishing_emails,
    load_legitimate_emails,
    create_diverse_spam_samples
)

class SimpleEmailTester:
    """Simple, clear testing for email classifier"""
    
    def __init__(self, model_path='enhanced_email_classifier.pkl'):
        self.model_path = model_path
        self.load_model()
        
    def load_model(self):
        """Load the trained model"""
        with open(self.model_path, 'rb') as f:
            saved = pickle.load(f)
        self.model = saved['model']
        self.vectorizer = saved['vectorizer']
        self.scaler = saved['scaler']
        self.feature_columns = saved['feature_columns']
    
    def test_single_email(self, email_text):
        """Test a single email and return simple result"""
        from scipy.sparse import hstack, csr_matrix
        
        # Extract features
        features, full_text = extract_all_features(email_text)
        processed = preprocess_text(full_text)
        
        # Vectorize
        text_vec = self.vectorizer.transform([processed])
        feat_values = [features.get(col, 0) for col in self.feature_columns]
        feat_scaled = self.scaler.transform(csr_matrix([feat_values]))
        combined = hstack([text_vec, feat_scaled])
        
        # Predict
        prediction = self.model.predict(combined)[0]
        probabilities = self.model.predict_proba(combined)[0]
        
        # Map to simple classification
        class_map = {0: 'SAFE', 1: 'SPAM', 2: 'DANGER'}
        verdict_map = {
            0: '✅ LEGITIMATE',
            1: '⚠️  SPAM/MARKETING',
            2: '🚨 PHISHING'
        }
        
        simple_class = class_map[prediction]
        confidence = probabilities[prediction] * 100
        
        return {
            'classification': simple_class,
            'confidence': f"{confidence:.0f}%",
            'verdict': verdict_map[prediction]
        }
    
    def run_quick_test(self):
        """Run quick accuracy test on sample emails"""
        print("\n" + "="*60)
        print("EMAIL CLASSIFIER - QUICK TEST")
        print("="*60)
        
        test_cases = [
            ('SAFE', """Subject: Team Meeting Tomorrow
From: john.doe@company.com

Hi team,

Just a reminder about our team meeting tomorrow at 10 AM in Conference Room B.

Best regards,
John"""),
            
            ('SAFE', """Subject: Password Reset Request
From: no-reply@accounts.google.com

Hello,

You recently requested to reset your password for your Google Account.

Your verification code is: 847293

This code will expire in 10 minutes.

Thanks,
The Google Accounts Team"""),
            
            ('SAFE', """Subject: Transaction Alert
From: alerts@chase.com

Dear Customer,

A transaction was processed on your Chase checking account ending in **4892.

Amount: $45.99
Merchant: Starbucks #1234
Date: January 15, 2024

Your current balance is $2,450.32

Chase Bank - Member FDIC"""),
            
            ('SPAM', """Subject: 40% OFF This Weekend Only!
From: deals@fashionstore.com
List-Unsubscribe: <mailto:unsubscribe@fashionstore.com>

Hi Sarah,

Don't miss our weekend sale - 40% off everything!

Shop Now: https://fashionstore.com/sale

Unsubscribe | Manage Preferences | View in Browser

Fashion Store Inc.
123 Fashion Ave, New York, NY 10001
© 2024 Fashion Store. All rights reserved."""),
            
            ('SPAM', """Subject: Download Our New App!
From: team@fooddelivery.com
List-Unsubscribe: <mailto:unsubscribe@fooddelivery.com>

Hello,

Get our app and enjoy 50% off your first order!

📱 Available on iOS and Android

Download: https://fooddelivery.com/app

Unsubscribe from promotional emails

FoodDelivery Team
456 Tech Blvd, Austin, TX 78701"""),
            
            ('DANGER', """Subject: URGENT: Account Suspended
From: security@paypa1-verify.com

Dear Customer,

Your PayPal account has been suspended due to suspicious activity.

You must verify immediately: http://192.168.1.100/verify

WARNING: You have 24 hours or account will be closed permanently.

Enter your password and credit card to confirm."""),
            
            ('DANGER', """Subject: Unauthorized Charge - Action Required
From: billing@amaz0n-secure.xyz

Dear Customer,

An unauthorized purchase of $499.99 has been charged.

If you did not authorize this, click here immediately:
http://bit.ly/cancel-order-now

You must update your billing information and password within 12 hours.

Amazon Billing""")
        ]
        
        correct = 0
        total = len(test_cases)
        
        print("\nTesting sample emails...\n")
        
        for expected, email in test_cases:
            result = self.test_single_email(email)
            is_correct = result['classification'] == expected
            correct += is_correct
            
            status = "✓" if is_correct else "✗"
            confidence_int = int(result['confidence'].replace('%', ''))
            
            # Color code confidence
            if confidence_int >= 80:
                conf_marker = "🟢"
            elif confidence_int >= 60:
                conf_marker = "🟡"
            else:
                conf_marker = "🔴"
            
            print(f"{status} Expected: {expected:7} | Got: {result['classification']:7} | {conf_marker} {result['confidence']}")
        
        accuracy = (correct / total) * 100
        
        print("\n" + "-"*60)
        print(f"RESULT: {correct}/{total} correct ({accuracy:.0f}% accuracy)")
        
        if accuracy >= 95:
            print("✅ EXCELLENT - Model is highly accurate!")
        elif accuracy >= 85:
            print("✅ GOOD - Model is working well!")
        elif accuracy >= 70:
            print("⚠️  FAIR - Model needs improvement")
        else:
            print("❌ POOR - Model needs retraining")
        
        print("="*60 + "\n")
        
        return accuracy
    
    def test_your_email(self):
        """Interactive testing - test your own email"""
        print("\n" + "="*60)
        print("TEST YOUR OWN EMAIL")
        print("="*60)
        print("\nPaste your email content below.")
        print("(Press Enter twice when done, or type 'quit' to exit)\n")
        
        while True:
            lines = []
            print("Email content:")
            while True:
                line = input()
                if line.lower() == 'quit':
                    return
                if line == '':
                    if lines:
                        break
                    else:
                        continue
                lines.append(line)
            
            if not lines:
                break
            
            email_text = '\n'.join(lines)
            result = self.test_single_email(email_text)
            
            print("\n" + "-"*60)
            print(f"RESULT: {result['verdict']}")
            print(f"Confidence: {result['confidence']}")
            print("-"*60 + "\n")
            
            cont = input("Test another email? (yes/no): ").lower()
            if cont not in ['yes', 'y']:
                break
    
    def full_accuracy_test(self, phishing_dir, csv_path):
        """Run complete accuracy test on real datasets"""
        print("\n" + "="*60)
        print("FULL ACCURACY TEST")
        print("="*60)
        
        print("\nLoading test data...")
        
        # Load data
        phishing_emails, phishing_labels = load_phishing_emails(phishing_dir, max_emails=100)
        legit_emails, legit_labels = load_legitimate_emails(csv_path, max_emails=150)
        spam_emails, spam_labels = create_diverse_spam_samples('../datasets/test_spam', num_samples=75)
        
        all_emails = legit_emails + spam_emails + phishing_emails
        all_labels = legit_labels + spam_labels + phishing_labels
        
        print(f"Testing on {len(all_emails)} emails...")
        print(f"  • {len(legit_emails)} legitimate")
        print(f"  • {len(spam_emails)} spam")
        print(f"  • {len(phishing_emails)} phishing")
        
        # Predict
        from scipy.sparse import hstack, csr_matrix
        predictions = []
        
        for email in all_emails:
            try:
                features, full_text = extract_all_features(email)
                processed = preprocess_text(full_text)
                
                text_vec = self.vectorizer.transform([processed])
                feat_values = [features.get(col, 0) for col in self.feature_columns]
                feat_scaled = self.scaler.transform(csr_matrix([feat_values]))
                combined = hstack([text_vec, feat_scaled])
                
                pred = self.model.predict(combined)[0]
                predictions.append(pred)
            except:
                predictions.append(-1)
        
        # Calculate metrics
        accuracy = accuracy_score(all_labels, predictions)
        precision, recall, f1, support = precision_recall_fscore_support(
            all_labels, predictions, average=None, labels=[0, 1, 2]
        )
        cm = confusion_matrix(all_labels, predictions, labels=[0, 1, 2])
        
        # Print ONE simple result
        print("\n" + "="*60)
        print("TEST RESULT")
        print("="*60)
        
        accuracy_percent = accuracy * 100
        critical = cm[2][0]  # Phishing marked as legitimate
        
        print(f"\n🎯 Model Accuracy: {accuracy_percent:.0f}%\n")
        
        # ONE clear verdict
        if accuracy_percent >= 95 and critical == 0:
            print("✅ EXCELLENT - Your model is ready to use!")
            print("   Safe emails detected correctly")
            print("   Spam emails detected correctly")
            print("   Dangerous emails detected correctly")
        elif accuracy_percent >= 90:
            if critical > 0:
                print(f"⚠️  WARNING - Model missed {critical} dangerous email(s)")
                print("   Consider retraining to improve safety")
            else:
                print("✅ GOOD - Your model works well!")
        elif accuracy_percent >= 80:
            print("⚠️  FAIR - Model needs improvement")
            print("   Consider retraining with more data")
        else:
            print("❌ POOR - Model needs retraining")
            print("   Accuracy too low for reliable use")
        
        print("\n" + "="*60 + "\n")
        
        return accuracy

def main():
    """Main function with simple menu"""
    
    MODEL_PATH = 'enhanced_email_classifier.pkl'
    CSV_PATH = "../datasets/emails.csv"
    PHISHING_DIR = "../datasets/phishing"
    
    # Check if model exists
    if not os.path.exists(MODEL_PATH):
        print("\n❌ Model not found!")
        print("Train the model first: python train_phishing_model.py\n")
        return
    
    tester = SimpleEmailTester(MODEL_PATH)
    
    print("\n" + "="*60)
    print("EMAIL CLASSIFIER TESTING")
    print("="*60)
    print("\nChoose an option:")
    print("  1. Quick Test (7 sample emails)")
    print("  2. Test Your Own Email (interactive)")
    print("  3. Full Accuracy Test (requires datasets)")
    print("  4. Exit")
    print("="*60)
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == '1':
        tester.run_quick_test()
    
    elif choice == '2':
        tester.test_your_email()
    
    elif choice == '3':
        if not os.path.exists(CSV_PATH) or not os.path.exists(PHISHING_DIR):
            print("\n❌ Datasets not found!")
            print(f"Need: {CSV_PATH} and {PHISHING_DIR}\n")
            return
        tester.full_accuracy_test(PHISHING_DIR, CSV_PATH)
    
    elif choice == '4':
        print("\nGoodbye!\n")
        return
    
    else:
        print("\n❌ Invalid choice!\n")

if __name__ == "__main__":
    main()