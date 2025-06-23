import tkinter as tk #in built module for GUI
from tkinter import tkk #tkk themed tkinter widgets, use Entry, Button , label with better styling,platform native lookinh
import string #useful constants and functions for handling strings, alphabets, numbers, punctuations
import re #built in regular expression engine, It is used to check patterns in string 
import secrets #it is designed for generating cryptographically secure random numbers. it is better than random for generating passwords,tokens and anything security related
import hashlib #provides the hashing algorithms, hashes the user's password before checking if it is breached, no full password is sent to API
import requests  #is a third party python library for sending HTTP requests easily, used to contact Have I been Pwned API

#evaluating the strength of the password by length, uppercase, lowercase, strings, and digits, and special characters
#we maintain a score variable to check the score and the maximum of 10 score is a very strong password and is suggested,score is based on the length, digit, special character
def evaluate_password(password):
    suggestions= []
    score=0
    
    if len(password)>=8:
        score +=1
    else:
        suggestions.append("Use at least 8 characters")
    
    if len(password)>=12:
        score+=1
    
    if re.search(r'[a-z],password'):
        score +=1
    else:
        suggestions.append("Add Lowercase letters")
        
    if re.search(r'[A-Z],password'):
        score +=1
    else:
        suggestions.append("Add Uppercase letters")

    if re.search(r'\d',password):
        score +=1
    else:
        suggestions.append("Add digits")
        
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]',password):
        score +=1
    else:
        suggestions.append("Add special characters")
        
    if len(set(password))>8:
        score +=1 
        
    if re.search(r'(.)\1\1',password):
        suggestions.append("Avoid repeated characters")
        
    if score <=2:
        strength="VERY WEAK!!!"
        color='red'
    elif score<=4:
        strength='WEAK!!!'
        color='orange'
    elif score<=6:
        strength='MODERATE!!!'
        color="blue"
    elif score >=8:
        strength=' VERY STRONG!!!'
        color='green'
        
    return strength, score, suggestions,color


        
    