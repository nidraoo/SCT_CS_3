# SCT_CS_3
Assessing the strength of the password based on length, uppercase, lowercase and special characters.   
A simple yet powerful Python GUI application that helps users **create**, **evaluate**, and **secure** passwords in real-time. Built using `tkinter`, this tool checks password strength, offers improvement suggestions, generates strong passwords, and detects if the entered password has been compromised in known data breaches.

## Features

- **Password Strength Evaluation**
  - Real-time analysis using length, character diversity, repetition checks, and entropy approximation.
  - Color-coded strength feedback (Very Weak → Very Strong).
  
- **Security Suggestions**
  - Clear, actionable tips to improve weak passwords.
  - Encourages strong security habits.

- **HaveIBeenPwned Integration**
  - Uses SHA1 and K-Anonymity to check if the password has appeared in data breaches.

- **Password Generator**
  - Generates cryptographically strong passwords using Python's `secrets` module.
  - Customizable password length (8–32 characters).

- **Show/Hide Password**
  - Toggle password visibility easily.

- **Copy to Clipboard**
  - One-click copy feature with visual confirmation.

- **Clear Functionality**
  - Reset all inputs and suggestions with a single click.

- **Custom UI Styling**
  - Styled with colored buttons, slider customization, modern fonts, and a responsive layout.

