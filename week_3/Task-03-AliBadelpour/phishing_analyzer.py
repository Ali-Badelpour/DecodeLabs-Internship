#!/usr/bin/env python3

# Project 3: Phishing Awareness Analysis
# DecodeLabs Cyber Security Internship - Week 3
# Author: Ali Badelpour
# Date: August 2026

# Description:
# A comprehensive phishing email analysis tool that identifies red flags,
# suspicious links, and deceptive tactics. This project bridges the gap
# between technical security and human psychology, demonstrating how
# attackers exploit cognitive triggers.

import re
from typing import Dict, List, Set
from datetime import datetime
import urllib.parse


# --- 1. Constants and Configuration ---

# Known malicious/suspicious domains (for demonstration)
SUSPICIOUS_DOMAINS: Set[str] = {
    "executive-update.com",
    "secure-login.net",
    "verify-account.org",
    "billing-update.info",
    "google-security-check.com",
    "microsoft-verify.net",
    "paypal-account.com",
    "amazon-billing.info",
    "appleid-verify.com",
    "bank-secure-login.com",
    "linkedin-verify.net",
    "dropbox-login.com",
}

# Red flag keywords (urgency, fear, authority)
RED_FLAG_KEYWORDS: Dict[str, str] = {
    "urgent": "Urgency",
    "immediate": "Urgency",
    "as soon as possible": "Urgency",
    "asap": "Urgency",
    "deadline": "Urgency",
    "expires": "Urgency",
    "expiring": "Urgency",
    "locked": "Fear",
    "suspended": "Fear",
    "compromised": "Fear",
    "unauthorized": "Fear",
    "breach": "Fear",
    "security alert": "Fear",
    "termination": "Fear",
    "legal action": "Fear",
    "strictly confidential": "Authority",
    "bypass standard procedure": "Authority",
    "do not discuss": "Authority",
    "CEO": "Authority",
    "executive": "Authority",
    "director": "Authority",
    "president": "Authority",
    "manager": "Authority",
    "bonus": "Greed",
    "free": "Greed",
    "prize": "Greed",
    "win": "Greed",
    "reward": "Greed",
    "gift": "Greed",
    "invoice": "Financial",
    "payment": "Financial",
    "wire transfer": "Financial",
    "bank account": "Financial",
    "credit card": "Financial",
    "billing": "Financial",
}

# Common URL shorteners (often used to hide malicious links)
URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "short.link", "rebrand.ly",
    "shorturl.at", "cutt.ly", "tiny.cc", "shorte.st"
}


# --- 2. Email Analysis Functions ---

class PhishingAnalyzer:
    """
    A comprehensive phishing email analyzer.
    Identifies red flags, suspicious links, and cognitive triggers.
    """

    def __init__(self):
        self.red_flags: List[Dict[str, str]] = []
        self.score: int = 0
        self.max_score: int = 100

    def analyze_email(self, subject: str, sender: str, body: str) -> Dict:
        """
        Analyze an email for phishing indicators.

        Args:
            subject: Email subject line
            sender: Sender email address (From field)
            body: Email body content

        Returns:
            Dictionary containing analysis results
        """
        self.red_flags = []
        self.score = 0

        analysis = {
            "subject": subject,
            "sender": sender,
            "body": body[:500] + "..." if len(body) > 500 else body,
            "red_flags": [],
            "risk_score": 0,
            "risk_level": "SAFE",
            "suspicious_links": [],
            "cognitive_triggers": [],
            "recommendation": "",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        # Step 1: Analyze sender domain
        self._analyze_sender(analysis, sender)

        # Step 2: Analyze subject line
        self._analyze_text(analysis, subject, "subject")

        # Step 3: Analyze body
        self._analyze_text(analysis, body, "body")

        # Step 4: Extract and analyze links
        self._analyze_links(analysis, body)

        # Step 5: Calculate risk score
        self._calculate_risk_score(analysis)

        # Step 6: Generate triage recommendation
        self._generate_recommendation(analysis)

        return analysis

    def _analyze_sender(self, analysis: Dict, sender: str) -> None:
        """Analyze the sender's email address for spoofing."""
        # Check if sender contains suspicious domain
        for domain in SUSPICIOUS_DOMAINS:
            if domain in sender.lower():
                self.red_flags.append({
                    "type": "Suspicious Domain",
                    "detail": 
                    f"Email sent from known suspicious domain: {domain}",
                    "severity": "High"
                })
                self.score += 15

        # Check for display name spoofing
        # (e.g., "CEO Name <hacker@gmail.com>")
        if "<" in sender and ">" in sender:
            display_name = sender[:sender.find("<")].strip()
            email = sender[sender.find("<") + 1:sender.find(">")]

            # Check if it looks like a legitimate name but free email service
            free_services = [
                "gmail.com", "yahoo.com",
                "hotmail.com", "outlook.com"
            ]
            if any(service in email.lower() for service in free_services):
                if len(display_name.split()) >= 2:  # Looks like a real name
                    self.red_flags.append({
                        "type": "Display Name Spoofing",
                        "detail": (
                            f"Legitimate-looking display name '{display_name}'"
                            f"using free email: {email}"
                        ),
                        "severity": "High"
                    })
                    self.score += 10

        # Check for lookalike domain (typosquatting)
        if ("decodelabs" in sender.lower()
                and "decodelabs.tech" not in sender.lower()):
            self.red_flags.append({
                "type": "Typosquatting",
                "detail": (
                    "Domain contains 'decodelabs' but is not "
                    f"the official domain: {sender}"
                ),
                "severity": "Critical"
            })
            self.score += 20

    def _analyze_text(self, analysis: Dict, text: str, source: str) -> None:
        """Analyze text for red flag keywords and cognitive triggers."""
        text_lower = text.lower()

        for keyword, category in RED_FLAG_KEYWORDS.items():
            if keyword in text_lower:
                # Check if it's already counted (avoid duplicates)
                existing = [rf for rf in self.red_flags
                            if rf["detail"] == keyword]
                if not existing:
                    self.red_flags.append({
                        "type": f"{category} Trigger",
                        "detail": (
                            f"'{keyword}' - Creates artificial "
                            f"{category.lower()} pressure"
                        ),
                        "severity": "Medium"
                    })

                # Track cognitive triggers
                if category not in analysis["cognitive_triggers"]:
                    analysis["cognitive_triggers"].append(category)

                self.score += 5

        # Check for requests to bypass security
        bypass_phrases = [
            "bypass standard procedure",
            "ignore security",
            "do not follow policy",
            "confidential"
        ]
        for phrase in bypass_phrases:
            if phrase in text_lower:
                self.red_flags.append({
                    "type": "Security Bypass",
                    "detail": (
                        "Explicitly requests bypassing security "
                        f"procedures: '{phrase}'"
                    ),
                    "severity": "Critical"
                })
                self.score += 15

        # Check for personal information requests
        personal_info = [
            "password", "ssn", "social security",
            "account number", "credit card", "mfa", "2fa"
        ]
        for item in personal_info:
            if item in text_lower:
                self.red_flags.append({
                    "type": "Data Request",
                    "detail": f"Requests sensitive information: '{item}'",
                    "severity": "Critical"
                })
                self.score += 15

    def _analyze_links(self, analysis: Dict, text: str) -> None:
        """Extract and analyze links for phishing indicators."""
        # Extract all URLs using regex
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)

        suspicious_links = []

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()

            # Remove www. prefix
            if domain.startswith("www."):
                domain = domain[4:]

            # Check if domain is in suspicious list
            if any(suspicious in domain for suspicious in SUSPICIOUS_DOMAINS):
                suspicious_links.append({
                    "url": url,
                    "reason": f"Domain matches suspicious list: {domain}"
                })
                self.score += 10

            # Check for URL shorteners
            if any(shortener in domain for shortener in URL_SHORTENERS):
                suspicious_links.append({
                    "url": url,
                    "reason": 
                    f"URL shortener used (hides destination): {domain}"
                })
                self.score += 8

            # Check for lookalike domain (homoglyph)
            if ("paypal" in domain
                    and domain != "paypal.com"
                    and domain != "www.paypal.com"):
                suspicious_links.append({
                    "url": url,
                    "reason": f"Potential lookalike/homoglyph domain: {domain}"
                })
                self.score += 15

            # Check if link leads to IP address (instead of domain)
            if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
                suspicious_links.append({
                    "url": url,
                    "reason": 
                    f"Direct IP address used instead of domain:{parsed.netloc}"  
                    # noqa: E501
                })
                self.score += 10

        analysis["suspicious_links"] = suspicious_links

        # Create red flags for suspicious links
        for link in suspicious_links:
            self.red_flags.append({
                "type": "Suspicious Link",
                "detail": link["reason"],
                "severity": "High"
            })

    def _calculate_risk_score(self, analysis: Dict) -> None:
        """Calculate overall risk score and level."""
        # Cap score at 100
        risk_score = min(self.score, 100)
        analysis["risk_score"] = risk_score

        if risk_score >= 70:
            analysis["risk_level"] = "CRITICAL - MALICIOUS"
        elif risk_score >= 40:
            analysis["risk_level"] = "HIGH - SUSPICIOUS"
        elif risk_score >= 15:
            analysis["risk_level"] = "MEDIUM - CAUTION"
        else:
            analysis["risk_level"] = "LOW - LIKELY SAFE"

    def _generate_recommendation(self, analysis: Dict) -> None:
        """Generate triage recommendation based on analysis."""
        risk_level = analysis["risk_level"]

        if risk_level == "CRITICAL - MALICIOUS":
            analysis["recommendation"] = (
                "🚨 IMMEDIATE BLOCK & REPORT - Delete email, block sender "
                "domain, report to security team, and notify all users."
            )
            analysis["action"] = "BLOCK"
        elif risk_level == "HIGH - SUSPICIOUS":
            analysis["recommendation"] = (
                "⚠️ WARN USER - Do not click links. Verify sender via "
                "out-of-band communication (phone call to known number)."
            )
            analysis["action"] = "WARN"
        elif risk_level == "MEDIUM - CAUTION":
            analysis["recommendation"] = (
                "🔍 PROCEED WITH CAUTION - Hover over links to verify "
                "destinations. Do not share sensitive information."
            )
            analysis["action"] = "CAUTION"
        else:
            analysis["recommendation"] = (
                "✅ LIKELY SAFE - Standard email. No immediate security "
                "concerns detected."
            )
            analysis["action"] = "CLOSE"

    def get_red_flags_report(self) -> str:
        """Generate a formatted report of all red flags."""
        if not self.red_flags:
            return "   ✅ No red flags detected."

        report = []
        for i, flag in enumerate(self.red_flags, 1):
            report.append(f"   {i}. [{flag['severity']}] {flag['type']}")
            report.append(f"      → {flag['detail']}")
        return "\n".join(report)

    def print_full_report(self, analysis: Dict) -> None:
        """Print a complete, formatted analysis report."""
        print("\n" + "=" * 70)
        print("🔎 PHISHING AWARENESS ANALYSIS REPORT")
        print("=" * 70)
        print(f"📅 Analysis Time: {analysis['timestamp']}")
        print("=" * 70)

        print(f"\n📧 SENDER: {analysis['sender']}")
        print(f"📝 SUBJECT: {analysis['subject']}")

        print(f"\n📊 RISK SCORE: {analysis['risk_score']}/100")
        print(f"⚠️ RISK LEVEL: {analysis['risk_level']}")

        print("\n🔴 RED FLAGS FOUND:")
        print(self.get_red_flags_report())

        print("\n🧠 COGNITIVE TRIGGERS DETECTED:")
        if analysis['cognitive_triggers']:
            for trigger in analysis['cognitive_triggers']:
                print(f"   - {trigger}")
        else:
            print("   - None detected")

        print("\n🔗 SUSPICIOUS LINKS:")
        if analysis['suspicious_links']:
            for link in analysis['suspicious_links']:
                print(f"   - {link['url']}")
                print(f"     → {link['reason']}")
        else:
            print("   - None detected")

        print(f"\n💡 RECOMMENDATION:")
        print(f"   {analysis['recommendation']}")
        print(f"🎯 ACTION: {analysis.get('action', 'N/A')}")

        print("\n" + "=" * 70)


# --- 3. Sample Phishing Email Library ---

SAMPLE_EMAILS = {
    "phishing_1": {
        "sender": "CEO John Smith <ceo.urgent@executive-update.com>",
        "subject": "IMMEDIATE ACTION REQUIRED: Wire Transfer Authorization",
        "body": """URGENT: Process the attached wire transfer 
        instruction immediately.

This is critical and must remain STRICTLY CONFIDENTIAL.
Do not discuss with anyone.
Bypass standard procedure.

Thank you,
CEO John Smith"""
    },
    "phishing_2": {
        "sender": "Support Team <security@google-security-check.com>",
        "subject": "Your Google Account Has Been Compromised",
        "body": """Dear User,

We have detected suspicious activity on your Google account.
Your password must be reset within 24 hours to prevent account suspension.

Click here to secure your account: https://google-security-check.com/verify

If you do not take action, your account will be permanently locked.

Google Security Team"""
    },
    "phishing_3": {
        "sender": "Finance Department <billing@amazon-billing.info>",
        "subject": "Your Amazon Prime Subscription Payment Failed",
        "body": """Dear Amazon Customer,

Your recent payment for Amazon Prime subscription has failed.
Please update your billing information immediately to avoid service 
interruption.

Update Payment: https://amazon-billing.info/update

If you have any questions, please contact our support team.

Amazon Billing Team"""
    },
    "phishing_4": {
        "sender": "Sarah Lee <sarah.lee@company.com>",
        "subject": "Q3 Project Status Update - Non-Urgent",
        "body": """Hi Team,

Please review the attached project status for Q3 at your earliest convenience.
No immediate action is required.

Thanks,
Sarah"""
    },
    "phishing_5": {
        "sender": "HR Department <hr@company.com>",
        "subject": "Important: 2026 Healthcare Benefits Update",
        "body": """Dear Employee,

Our healthcare benefits provider has updated their enrollment system.
Please complete the required questionnaire by Friday to ensure 
continued coverage.

You can access the questionnaire here:
https://company-benefits.secure-portal.com/enroll

Best,
HR Team"""
    }
}


# --- 4. Main Program ---

def print_banner():
    """Print the DecodeLabs banner."""
    print("=" * 70)
    print("🎣 DECODELABS - PHISHING AWARENESS ANALYZER")
    print("🔐 Cybersecurity Project 3: Threat Identification")
    print("=" * 70)
    print("\n💡 This tool analyzes emails for phishing indicators,")
    print("💡 identifies red flags, and provides triage recommendations.")
    print()


def display_sample_emails():
    """Display available sample emails for analysis."""
    print("\n📧 Available Sample Emails:")
    print("-" * 50)
    for key, email in SAMPLE_EMAILS.items():
        print(f"   {key}: {email['subject']}")
    print()


def main():
    """
    Main program loop.
    """
    print_banner()

    analyzer = PhishingAnalyzer()

    while True:
        print("\n📌 MENU:")
        print("   1. 🎯 Analyze a sample phishing email")
        print("   2. 📝 Analyze a custom email")
        print("   3. 📚 View sample email library")
        print("   4. 📖 Learn about phishing techniques")
        print("   5. 🚪 Exit")

        choice = input("\nSelect an option (1-5): ").strip()

        if choice == '5' or choice.lower() == 'exit':
            print("\n👋 Exiting. Stay vigilant and secure!")
            break

        if choice == '1':
            # Analyze sample email
            display_sample_emails()
            sample_key = input(
                "\nEnter sample email key (e.g., 'phishing_1'): "
            ).strip()

            if sample_key in SAMPLE_EMAILS:
                email = SAMPLE_EMAILS[sample_key]
                print(f"\n📧 Analyzing: {email['subject']}")
                analysis = analyzer.analyze_email(
                    email['subject'],
                    email['sender'],
                    email['body']
                )
                analyzer.print_full_report(analysis)
            else:
                print("⚠️ Invalid sample key. Please try again.")

        elif choice == '2':
            # Analyze custom email
            print("\n📝 Enter email details:")
            sender = input("   Sender Email (From field): ").strip()
            subject = input("   Subject Line: ").strip()
            print(
                "   Body (Enter multiple lines, type 'END' on a new line "
                "to finish):"
            )

            body_lines = []
            while True:
                line = input("   ")
                if line.strip().upper() == 'END':
                    break
                body_lines.append(line)

            body = "\n".join(body_lines)

            if not sender or not subject or not body:
                print("⚠️ All fields are required. Please try again.")
                continue

            analysis = analyzer.analyze_email(subject, sender, body)
            analyzer.print_full_report(analysis)

        elif choice == '3':
            # View sample library
            print("\n📚 SAMPLE EMAIL LIBRARY")
            print("=" * 70)
            for key, email in SAMPLE_EMAILS.items():
                print(f"\n[{key}]")
                print(f"   From: {email['sender']}")
                print(f"   Subject: {email['subject']}")
                print(f"   Body: {email['body'][:100]}...")
            print("\n" + "=" * 70)

        elif choice == '4':
            # Learning section
            print("\n📖 PHISHING TECHNIQUES & RED FLAGS")
            print("=" * 70)
            print("\n🔴 KEY RED FLAGS:")
            print("   1. Sender-Domain Mismatch - Display name conflicts with "
                  "actual routing domain")
            print("   2. Urgency/Threats - Creates artificial pressure to "
                  "bypass logic")
            print("   3. Requests for Sensitive Info - Unexpected prompts for "
                  "passwords or MFA codes")
            print("   4. Suspicious Links - URL shorteners, lookalike domains,"
                  "IP addresses")
            print("   5. Security Bypass - Explicit instructions to ignore "
                  "standard procedures")
            print("   6. Authority Claims - Impersonating executives, IT, or "
                  "law enforcement")
            print("   7. Typosquatting - Misspellings of legitimate domains "
                  "(amazOn.com)")
            print("   8. Homoglyph Attacks - Visually similar characters from "
                  "other alphabets")

            print("\n🧠 COGNITIVE TRIGGERS:")
            print("   - AUTHORITY: Impersonating trusted figures to demand "
                  "compliance")
            print("   - URGENCY: Creating time pressure to reduce rational "
                  "thinking")
            print("   - FEAR: Threatening negative consequences (account lock,"
                  "legal action)")
            print("   - GREED: Promising unearned rewards or prizes")
            print("   - CURIOSITY: Exploiting the need to fill knowledge gaps")

            print("\n🛡️ BEST DEFENSES:")
            print("   1. PAUSE - Stop and think before acting")
            print("   2. VERIFY - Confirm via out-of-band communication")
            print("   3. REPORT - Use internal reporting channels")
            print("   4. HOVER - Check link destinations before clicking")
            print("   5. NO SENSITIVE DATA - Never share passwords or MFA "
                  "codes via email")
            print("=" * 70)

        else:
            print("⚠️ Invalid option. Please select 1-5.")


if __name__ == "__main__":
    main()