# 🔐 Basic Encryption & Decryption (Caesar Cipher)

## 📌 Project Overview
**Project**: Basic Encryption & Decryption  
**Domain**: Cyber Security  
**Week**: 2  
**Batch**: 2026  
**Organization**: DecodeLabs  

This project implements the **Caesar Cipher**, one of the oldest and most fundamental encryption techniques. It demonstrates data confidentiality, the mathematical relationship between encryption and decryption, and the critical weaknesses of simple cryptographic systems.

---

## 🎯 Objectives
- ✅ Implement encryption using the Caesar Cipher (shift logic)
- ✅ Implement decryption (reverse shift)
- ✅ Handle edge cases (spaces, punctuation, case preservation)
- ✅ Allow user-defined shift key (1-25)
- ✅ Demonstrate brute-force decryption (showing cipher weakness)
- ✅ Perform frequency analysis to break the cipher

---

## ⚙️ How It Works

### Encryption Formula
E(x) = (x + k) % 26

text
Where:
- `x` = position of the letter (A=0, B=1, ..., Z=25)
- `k` = shift key (1-25)

### Decryption Formula
D(x) = (x - k) % 26

text

### Example
| Plain | Shift (K) | Encryption | Cipher |
| :--- | :--- | :--- | :--- |
| A | 3 | (0+3)%26=3 | D |
| Hello | 3 | - | Khoor |

---

## 🛠️ Features
- ✅ **Encryption**: Shift each letter by a user-defined key
- ✅ **Decryption**: Reverse the shift to recover the original text
- ✅ **Case Preservation**: Uppercase/lowercase letters are handled separately
- ✅ **Non-Alphabetic Characters**: Spaces, numbers, and punctuation are preserved
- ✅ **Customizable Shift**: User can choose any shift between 1-25
- ✅ **Brute-Force Mode**: Test all 25 possible shifts to crack ciphertext
- ✅ **Frequency Analysis**: Demonstrate how letter frequency breaks the cipher
- ✅ **Educational Mode**: Learn about the history and weaknesses of Caesar Cipher

---

## 🔧 Installation & Usage

### Prerequisites
- Python 3.6 or higher (no external libraries required)

### Run the Script
```bash
python caesar_cipher.py
