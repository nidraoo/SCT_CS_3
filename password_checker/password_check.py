import tkinter as tk #in built module for GUI
from tkinter import tkk #tkk themed tkinter widgets, use Entry, Button , label with better styling,platform native lookinh
import string #useful constants and functions for handling strings, alphabets, numbers, punctuations
import re #built in regular expression engine, It is used to check patterns in string 
import secrets #it is designed for generating cryptographically secure random numbers. it is better than random for generating passwords,tokens and anything security related
import hashlib #provides the hashing algorithms, hashes the user's password before checking if it is breached, no full password is sent to API
import requests  #is a third party python library for sending HTTP requests easily, used to contact Have I been Pwned API