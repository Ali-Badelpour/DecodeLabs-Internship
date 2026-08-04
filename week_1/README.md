# 🔐 Password Strength Checker

## 📌 Project Overview
**Project**: Password Strength Checker  
**Domain**: Cyber Security  
**Week**: 1  
**Batch**: 2026  
**Organization**: DecodeLabs  

This project is a Python-based password strength evaluation tool. It analyzes a user's password based on length, character variety, entropy, and checks against common leaked passwords. It provides a security rating (Weak/Medium/Strong) and actionable feedback for improvement.

---

## 🎯 Objectives
- ✅ Implement **defensive security logic** using Python
- ✅ Practice **data validation** and **entropy calculation**
- ✅ Understand and mitigate **timing attacks** using `hmac.compare_digest()`
- ✅ Build a real-world portfolio piece for cybersecurity professionals

---

## 🛠️ Features
- ✅ **Length validation**: 8+ characters recommended, 12+ is better
- ✅ **Character variety checking**: uppercase, lowercase, digits, symbols
- ✅ **Dictionary check**: against 500+ common leaked passwords from `rockyou.txt`
- ✅ **Entropy calculation**: Shannon entropy to measure randomness
- ✅ **Secure comparison**: Constant-time comparison to mitigate timing attacks
- ✅ **Password generator**: Cryptographically strong password generation using `secrets`
- ✅ **User-friendly feedback**: Specific, actionable improvement suggestions

---

## 🔧 Installation & Usage

### Prerequisites
- Python 3.6 or higher (no external libraries required)

### Run the Script
```bash
python password_strength_checker.py
