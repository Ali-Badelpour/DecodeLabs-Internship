#!/usr/bin/env python3

# Project 2: Basic Encryption and Decryption
# DecodeLabs Cyber Security Internship - Week 2
# Author: Ali Badelpour
# Date: August 2026

# Description:
# A professional implementation of the Caesar Cipher that demonstrates
# fundamental encryption and decryption concepts. This project covers:
# - Data confidentiality through basic cryptography
# - Input validation and edge case handling
# - Preserving spaces, punctuation, and case
# - Customizable shift key
# - Brute-force decryption (demonstrating cipher weakness)

import sys
import string

# --- 1. Constants and Configuration ---

# Printable ASCII characters
LOWERCASE = string.ascii_lowercase  # 'abcdefghijklmnopqrstuvwxyz'
UPPERCASE = string.ascii_uppercase  # 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ALPHABET_SIZE = 26


# --- 2. Core Encryption/Decryption Logic ---

def caesar_encrypt(text: str, shift: int) -> str:
    """
    Encrypt text using the Caesar Cipher.

    How it works:
        - Each letter is shifted by 'shift' positions in the alphabet.
        - Case is preserved (uppercase stays uppercase, lowercase stays
        lowercase)
        - Non-alphabetic characters (spaces, numbers, punctuation) are left
        unchanged

    Example:
        caesar_encrypt("Hello World!", 3) -> "Khoor Zruog!"

    Args:
        text: The plaintext to encrypt
        shift: The number of positions to shift (0-25)

    Returns:
        The encrypted (cipher) text
    """

    shift = shift % ALPHABET_SIZE  # Normalize shift to 0-25
    result = []

    for char in text:
        if char.isupper():
            # Shift uppercase letter
            original_pos = ord(char) - ord('A')
            new_pos = (original_pos + shift) % ALPHABET_SIZE
            result.append(chr(new_pos + ord('A')))  
        elif char.islower():
            # Shift lowercase letter
            original_pos = ord(char) - ord('a')
            new_pos = (original_pos + shift) % ALPHABET_SIZE
            result.append(chr(new_pos + ord('a')))  
        else:
            # Preserve non-alphabetic characters
            result.append(char)

    return ''.join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    """
    Decrypt text using the Caesar Cipher.

    Decryption is simply encryption with a negative shift.

    Args:
        text: The ciphertext to decrypt
        shift: The number of positions to shift (0-25)

    Returns:
        The decrypted (plain) text
    """
    return caesar_encrypt(text, -shift)


# --- 3. Brute-force Decryption (Demonstrating Cipher Weakness) ---

def brute_force_caesar(ciphertext: str) -> list:
    """
    Try all 25 possible shifts to find the original plaintext.

    This demonstrates the fundamental weakness of the Caesar Cipher:
    tiny key space (only 25 possible shifts) makes it vulnerable to brute-force
    attacks.

    Args:
        ciphertext: The encrypted text to crack

    Returns:
        List of tuples (shift, plaintext) for all possible shifts
    """
    results = []
    for shift in range(1, ALPHABET_SIZE):  # 1 to 25
        plaintext = caesar_decrypt(ciphertext, shift)
        results.append((shift, plaintext))
    return results


# --- 4. Security Analysis: Frequency Distribution ---

def analyze_frequency(text: str) -> dict:
    """
    Calculate letter frequency distribution in the text.

    This is used to demonstrate how frequency analysis can break Caesar Cipher.

    Args:
        text: The text to analyze

    Returns:
        Dictionary of letter -> frequency percentage
    """
    # Filter only alphabetic characters
    letters = [char.lower() for char in text if char.isalpha()]
    total = len(letters)

    if total == 0:
        return {}

    frequency = {}
    for letter in letters:
        frequency[letter] = frequency.get(letter, 0) + 1

    # Convert to Percentages
    for letter in frequency:
        frequency[letter] = (frequency[letter] / total) * 100

    return frequency


# --- 5. User Interface ---

def print_banner():
    """Print the DecodeLabs banner."""
    print("=" * 60)
    print("🔒 DECODELABS - CAESAR CIPHER TOOL")
    print("🔐 Cybersecurity Project 2: Data Confidentiality")
    print("=" * 60)
    print("\n💡 The Caesar Cipher is one of the oldest encryption techniques.")
    print("💡 It shifts each letter by a fixed number of positions.\n")


def print_frequency_analysis(text: str):
    """Display frequency analysis of a text."""
    freq = analyze_frequency(text)
    if not freq:
        return

    print("\n📊 Letter Frequency Analysis:")
    print("-" * 40)
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    for letter, percentage in sorted_freq[:10]:
        bar = "█" * int(percentage)
        print(f"   {letter}: {bar} ({percentage:.1f}%)")
    print("-" * 40)


def display_brute_force_results(results: list):
    """
    Display brute-force results in a readable format.
    Shows only the most likely results (with spaces and common words).
    """
    print("\n🔍 Brute-Force Results (All 25 Shifts):")
    print("=" * 60)

    # Filter to show only results that look like English
    # This is a simple heuristic: check if plaintext has common words
    common_words = ["the", "and", "for", "are", "but", "not", "you", "all",
                    "can", "had", "her", "was", "one", "our", "out"]

    print("   Shift | Decrypted Text")
    print("   " + "-" * 50)

    for shift, plaintext in results:
        # Check if plaintext contains any common English word
        score = sum(1 for word in common_words
                    if word in plaintext.lower().split())
        if score > 0:
            print(f"   {shift:>5} | {plaintext}  ⭐ (Score: {score})")
        else:
            print(f"   {shift:>5} | {plaintext}")

    print("=" * 60)
    print("💡 The Caesar Cipher is vulnerable to brute-force attacks.")
    print("💡 With only 25 possible shifts, an attacker can "
          "crack it instantly.")


def main():
    """
    Main program loop.
    """
    print_banner()

    while True:
        print("\n📌 MENU:")
        print("   1. 🔐 Encrypt a message")
        print("   2. 🔓 Decrypt a message")
        print("   3. 🔍 Brute-force crack a ciphertext")
        print("   4. 📊 Analyze letter frequency")
        print("   5. 📖 Learn about the Caesar Cipher")
        print("   6. 🚪 Exit")

        choice = input("\nSelect an option (1-6): ").strip()

        if choice == '6' or choice.lower() == 'exit':
            print("\n👋 Exiting. Stay secure!")
            break

        if choice == '1':
            # ENCRYPT
            text = input("\n📝 Enter the message to encrypt: ")
            if not text:
                print("⚠️ Please enter a valid message.")
                continue

            shift = input("🔑 Enter shift key (1-25, default=3): ").strip()
            try:
                shift = int(shift) if shift else 3
                shift = shift % ALPHABET_SIZE
                if shift == 0:
                    shift = 3
            except ValueError:
                print("⚠️ Invalid input. Using default shift: 3")
                shift = 3

            encrypted = caesar_encrypt(text, shift)
            print(f"\n✅ Encrypted (Ciphertext): {encrypted}")
            print(f"   (Shift: {shift})")

        elif choice == '2':
            # DECRYPT
            text = input("\n📝 Enter the message to decrypt: ")
            if not text:
                print("⚠️ Please enter a valid message.")
                continue

            shift = input("🔑 Enter shift key (1-25, default=3): ").strip()
            try:
                shift = int(shift) if shift else 3
                shift = shift % ALPHABET_SIZE
                if shift == 0:
                    shift = 3
            except ValueError:
                print("⚠️ Invalid input. Using default shift: 3")
                shift = 3

            decrypted = caesar_decrypt(text, shift)
            print(f"\n✅ Decrypted (Plaintext): {decrypted}")
            print(f"   (Shift: {shift})")

        elif choice == '3':
            # BRUTE-FORCE
            text = input("\n📝 Enter the ciphertext to crack: ")
            if not text:
                print("⚠️ Please enter a valid message.")
                continue

            print("\n🔍 Attempting to crack the ciphertext...")
            results = brute_force_caesar(text)
            display_brute_force_results(results)

        elif choice == '4':
            # FREQUENCY ANALYSIS
            text = input("\n📝 Enter text to analyze: ")
            if not text:
                print("⚠️ Please enter a valid message.")
                continue

            print_frequency_analysis(text)
            print("\n💡 In English, 'E' is the most common letter (≈12.7%).")
            print("💡 This weakness allows frequency analysis to "
                  "break Caesar Cipher.")

        elif choice == '5':
            # LEARNING SECTION
            print("\n📖 THE CAESAR CIPHER")
            print("=" * 60)
            print("📜 History:")
            print("   Named after Julius Caesar, who used it to communicate")
            print("   with his generals. It is one of the oldest and simplest")
            print("   known encryption techniques.\n")

            print("⚙️ How it works:")
            print("   - Each letter is shifted by a fixed number (shift key)")
            print("   - Example: Shift=3 -> A→D, B→E, C→F, ...")
            print("   - Formula: C = (P + K) % 26")
            print("   Where: C = Cipher letter, P = Plain letter, K = Shift\n")

            print("🔴 Weaknesses:")
            print("   - Only 25 possible shifts (brute-force vulnerability)")
            print("   - Preserves letter frequency "
                  "(vulnerable to frequency analysis)")
            print("   - Does not change the structure of the text")
            print("   - Not used in modern cryptography "
                  "(secure systems use AES)\n")

            print("🛡️ Modern Encryption uses:")
            print("   - 128-bit or 256-bit keys (trillions of possibilities)")
            print("   - XOR operations and complex mathematics")
            print("   - Confusion and diffusion (AES, RSA)\n")
            print("=" * 60)

        else:
            print("⚠️ Invalid option. Please select 1-6.")


if __name__ == "__main__":
    main()