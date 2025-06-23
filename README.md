# SCT_CS_3
Assessing the strength of the password based on length, uppercase, lowercase and special characters.   
A simple yet powerful Python GUI application that helps users **create**, **evaluate**, and **secure** passwords in real-time. Built using `tkinter`, this tool checks password strength, offers improvement suggestions, generates strong passwords, and detects if the entered password has been compromised in known data breaches.

## Features

- **Real-time strength evaluation** based on password length, use of upper/lowercase letters, digits, special characters, and character repetition.
- **Data breach check** powered by [Have I Been Pwned API](https://haveibeenpwned.com/API/v3#PwnedPasswords) — alerts if the password has been exposed.
- **Actionable suggestions** to improve password quality dynamically.
- **Strong password generator** with adjustable length (via slider).
- **Show/Hide password toggle** for visibility control.
- **Copy to clipboard** functionality for quick reuse.
- **Clear fields** with a single button click.
- **User-friendly interface** with clean design and responsive layout.

## Tech Stack

- **Python 3.10+**
- **Tkinter** for GUI
- **`hashlib`**, **`requests`**, **`secrets`**, and **`re`** modules for backend logic and security

## How It Works – Password Evaluator & Generator

1. **Live Analysis:**
   - Password is analyzed in real-time as you type.
2. **Strength Criteria:**
   - Based on length, use of upper/lowercase, digits, special characters, uniqueness, and repetition.
3. **Scoring & Feedback:**
   - Strength is categorized (Very Weak → Very Strong) with improvement suggestions.
4. **Breach Check:**
   - Password is securely checked via the [Have I Been Pwned](https://haveibeenpwned.com/) API using SHA-1 hashing (only partial hash is sent).
5. **Extras:**
   - Generate secure passwords  
   - Copy to clipboard  
   - Clear input  
   - Toggle password visibility  
   - All via a clean `tkinter` GUI




