#!/usr/bin/env python3

# Project 1: Password Strength Checker
# DecodeLabs Cyber Security Internship - Week 1
# Author: Ali Badelpour
# Date: July 2026

# Description:
# A professional, security-focused password strength checker that evaluates
# password entropy, checks against common leaked passwords, and provides
# actionable feedback to the user.

import re
import math
from typing import Dict, Tuple, Set
import secrets
import string

# --- 1. Constants and Configuration ---

# Embedded Top 500 common passwords from `rockyou.txt`
common_password_raw = """
123456
12345
123456789
password
iloveyou
princess
1234567
rockyou
12345678
abc123
nicole
daniel
babygirl
monkey
lovely
jessica
654321
michael
ashley
qwerty
111111
iloveu
000000
michelle
tigger
sunshine
chocolate
password1
soccer
anthony
friends
butterfly
purple
angel
jordan
liverpool
justin
loveme
fuckyou
123123
football
secret
andrea
carlos
jennifer
joshua
bubbles
1234567890
superman
hannah
amanda
loveyou
pretty
basketball
andrew
angels
tweety
flower
playboy
hello
elizabeth
hottie
tinkerbell
charlie
samantha
barbie
chelsea
lovers
teamo
jasmine
brandon
666666
shadow
melissa
eminem
matthew
robert
danielle
forever
family
jonathan
987654321
computer
whatever
dragon
vanessa
cookie
naruto
summer
sweety
spongebob
joseph
junior
softball
taylor
yellow
daniela
lauren
mickey
princesa
alexandra
alexis
jesus
estrella
miguel
william
thomas
beautiful
mylove
angela
poohbear
patrick
iloveme
sakura
adrian
alexander
destiny
christian
121212
sayang
america
dancer
monica
richard
112233
princess1
555555
diamond
carolina
steven
rangers
louise
orange
789456
999999
shorty
11111
nathan
snoopy
gabriel
hunter
cherry
killer
sandra
alejandro
buster
george
brittany
alejandra
patricia
rachel
tequiero
7777777
cheese
159753
arsenal
dolphin
antonio
heather
david
ginger
stephanie
peanut
blink182
sweetie
222222
beauty
987654
victoria
honey
00000
fernando
pokemon
maggie
corazon
chicken
pepper
cristina
rainbow
kisses
manuel
myspace
rebelde
angel1
ricardo
babygurl
heaven
55555
baseball
martin
greenday
november
alyssa
madison
mother
123321
123abc
mahalkita
batman
september
december
morgan
mariposa
maria
gabriela
iloveyou2
bailey
jeremy
pamela
kimberly
gemini
shannon
pictures
asshole
sophie
jessie
hellokitty
claudia
babygirl1
angelica
austin
mahalko
victor
horses
tiffany
mariana
eduardo
andres
courtney
booboo
kissme
harley
ronaldo
iloveyou1
precious
october
inuyasha
peaches
veronica
chris
888888
adriana
cutie
james
banana
prince
friend
jesus1
crystal
celtic
zxcvbnm
edward
oliver
diana
samsung
freedom
angelo
kenneth
master
scooby
carmen
456789
sebastian
rebecca
jackie
spiderman
christopher
karina
johnny
hotmail
0123456789
school
barcelona
august
orlando
samuel
cameron
slipknot
cutiepie
monkey1
50cent
bonita
kevin
bitch
maganda
babyboy
casper
brenda
adidas
kitten
karen
mustang
isabel
natalie
cuteako
javier
789456123
123654
sarah
bowwow
portugal
laura
777777
marvin
denise
tigers
volleyball
jasper
rockstar
january
fuckoff
alicia
nicholas
flowers
cristian
tintin
bianca
chrisbrown
chester
101010
smokey
silver
internet
sweet
strawberry
garfield
dennis
panget
francis
cassie
benfica
love123
696969
asdfgh
lollipop
olivia
cancer
camila
qwertyuiop
superstar
harrypotter
ihateyou
charles
monique
midnight
vincent
christine
apples
scorpio
jordan23
lorena
andreea
mercedes
katherine
charmed
abigail
rafael
icecream
mexico
brianna
nirvana
aaliyah
pookie
johncena
lovelove
fucker
abcdef
benjamin
131313
gangsta
brooke
333333
hiphop
aaaaaa
mybaby
sergio
welcome
metallica
julian
travis
myspace1
babyblue
sabrina
michael1
jeffrey
stephen
love
dakota
catherine
badboy
fernanda
westlife
blondie
sasuke
smiley
jackson
simple
melanie
steaua
dolphins
roberto
fluffy
teresa
piglet
ronald
slideshow
asdfghjkl
minnie
newyork
jason
raymond
santiago
jayson
88888888
5201314
jerome
gandako
muffin
gatita
babyko
246810
sweetheart
chivas
ladybug
kitty
popcorn
alberto
valeria
cookies
leslie
jenny
nicole1
12345678910
leonardo
jayjay
liliana
dexter
sexygirl
232323
amores
rockon
christ
babydoll
anthony1
marcus
bitch1
fatima
miamor
lover
chris1
single
eeyore
lalala
252525
scooter
natasha
skittles
brooklyn
colombia
159357
teddybear
winnie
happy
manutd
123456a
britney
katrina
christina
pasaway
cocacola
mahal
grace
linda
albert
tatiana
london
cantik
0123456
lakers
marie
teiubesc
147258369
charlotte
natalia
francisco
amorcito
smile
paola
angelito
manchester
hahaha
elephant
mommy1
shelby
147258
kelsey
genesis
amigos
snickers
xavier
"""

# Convert to a lightning-fast Set for O(1) lookups
common_passwords: Set[str] = set(common_password_raw.strip().splitlines())

# --- 2. Validation (Gatekeeper Rule) ---

def validate_input(password: str) -> bool:
    """
    Validate the input before any processing.
    Returns True if valid, False otherwise.
    """
    if not isinstance(password, str):
        return False
    if len(password) == 0:
        return False
    # Check for any non-printable characters
    if not all(31 < ord(char) < 127 for char in password):
        return False
    return True

# --- 3. Entropy and Strength Calculation ---

def calculate_entropy(password: str) -> float:
    """
    Calculate the Shannon entropy of the password.
    Higher entropy = more random = stronger.
    """
    if not password:
        return 0.0
    
    char_counts = {}
    for char in password:
        char_counts[char] = char_counts.get(char, 0) + 1

    entropy = 0.0
    length = len(password)
    for count in char_counts.values():
        probability = count / length
        # Use math.log2() for float (correct way to calculate log base 2)
        entropy -= probability * math.log2(probability)
    
    return entropy

def evaluate_strength(password: str) -> Tuple[str, int, Dict[str, bool]]:
    """
    Evaluate password strength based on multiple criteria.
    Returns: (strength_label, score, details_dict)
    """
    score = 0
    details = {
        "length_ok": False,
        "has_uppercase": False,
        "has_lowercase": False,
        "has_digit": False,
        "has_symbol": False,
        "not_common": False,
        "entropy_high": False,
    }

    # Criterion 1: Length (>= 8 is good, >= 12 is better)
    length = len(password)
    if length >= 12:
        score += 2
        details["length_ok"] = True
    elif length >= 8:
        score += 1
        details["length_ok"] = True
    else:
        details["length_ok"] = False
    
    # Criterion 2: Character Variety
    if re.search(r'[A-Z]', password):
        score += 1
        details["has_uppercase"] = True
    if re.search(r'[a-z]', password):
        score += 1 
        details["has_lowercase"] = True
    if re.search(r'\d', password):
        score += 1 
        details["has_digit"] = True
    if re.search(r'[!@#$%^&*()\-_=+[\]{};:\'",.<>?/`~]', password):
        score += 1
        details["has_symbol"] = True
    
    # Criterion 3: Check against Common Passwords
    #  (Mitigates Dictionary Attacks)
    if password in common_passwords:
        details["not_common"] = False
    else:
        score += 2  # Bonus for not being a common password
        details["not_common"] = True
    
    # Criterion 4: Entropy Check
    entropy = calculate_entropy(password)
    if entropy > 3.5:
        score += 1
        details["entropy_high"] = True
    else:
        details["entropy_high"] = False
    
    # Determine Strength Label (Standardized to Uppercase)
    if score >= 7:
        return "STRONG", score, details
    elif score >= 4:
        return "MEDIUM", score, details
    else:
        return "WEAK", score, details

# --- 4. User Interface and Reporting ---

def generate_feedback(password: str, strength: str, score: int, 
                      details: Dict[str, bool]) -> str:
    """
    Generate human-readable feedback based on the evaluation.
    """
    feedback = []
    feedback.append(f"🔐 Password Strength: {strength} (Score: {score}/9)")
    
    if strength == "WEAK":
        feedback.append("❌ Your password is too weak. Consider the following improvements:")
    elif strength == "MEDIUM":
        feedback.append("⚠️ Your password is decent but could be stronger. Suggestions:")
    else:  # STRONG
        feedback.append("✅ Excellent! Your password is strong and secure.")
    
    # Specific suggestions
    if not details["length_ok"]:
        feedback.append("   - Use at least 8 characters (12+ is even better).")
    if not details["has_uppercase"]:
        feedback.append("   - Add at least one UPPERCASE letter (A-Z).")
    if not details["has_lowercase"]:
        feedback.append("   - Add at least one lowercase letter (a-z).")
    if not details["has_digit"]:
        feedback.append("   - Add at least one digit (0-9).")
    if not details["has_symbol"]:
        feedback.append("   - Add at least one special character (!@#$%^&*).")
    if not details["not_common"]:
        feedback.append("   - Avoid common or easily guessable passwords.")
    if not details["entropy_high"]:
        feedback.append("   - Use a mix of unrelated characters (avoid patterns).")
    
    return "\n".join(feedback)

# --- 5. Password Generator ---

def generate_strong_password(length: int = 16) -> str:
    """
    Generate a cryptographically strong password.
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# --- 6. Main Program ---

def main():
    """
    Main program loop.
    """
    print("=" * 60)
    print("🔒 DECODELABS - PASSWORD STRENGTH CHECKER")
    print("🔐 Cybersecurity Project 1: Defensive Logic")
    print("=" * 60)
    print("\n💡 Tip: Type 'g' to generate a strong password")
    print("💡 Tip: Type 'exit' or 'e' to quit\n")
    
    while True:
        # Step 1: Input
        password = input("🔑 Enter a password to test "
        "(or type 'exit'/'e' to quit, 'g' to generate): ")
        
        if password.lower() == 'exit' or password.lower() == 'e':
            print("👋 Exiting. Stay secure!")
            break
        
        # Password Generator Feature
        if password.lower() == 'g':
            generated = generate_strong_password()
            print(f"\n✅ Generated Strong Password: {generated}\n")
            continue
        
        # Step 2: Validation (Gatekeeper Rule)
        if not validate_input(password):
            print("⚠️ Invalid input. Please use standard printable characters only.")
            continue
        
        # Step 3: Process (Strength Evaluation)
        strength, score, details = evaluate_strength(password)
        
        # Step 4: Output (Reporting)
        feedback = generate_feedback(password, strength, score, details)
        print("\n" + feedback)
        
        # Show entropy for advanced users
        entropy = calculate_entropy(password)
        print(f"📊 Entropy Score: {entropy:.2f} bits per character")
        print("-" * 60)

if __name__ == "__main__":
    main()