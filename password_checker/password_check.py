import tkinter as tk #in built module for GUI
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
    
    if re.search(r'[a-z]',password):
        score +=1
    else:
        suggestions.append("Add Lowercase letters")
        
    if re.search(r'[A-Z]',password):
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
    elif score <=7:
        strength='STRONG!!!'
        color='green'
    else:
        strength='VERY STRONG!!!'
        color='black'
        
    return strength,suggestions,color

#pwned passwords API chechker
def check_pwned_password(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper() #Hashes the password using SHA-1, and converts the result to uppercase hexadecimal.
    prefix,suffix = sha1[:5],sha1[5:] #This is the core of the k-Anonymity model, ensuring only the first 5 characters are sent over the internet.
    try:
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}') #This keeps your actual password or full hash private and secure. Sends an HTTP GET request to the HIBP API using only the prefix of the hash.The API responds with hundreds of suffixes and breach counts that match the prefix.
        if response.status_code != 200: #If the response isn't successful (not HTTP 200), returns 'API ERROR'.
            return 'API ERROR'
        hashes =(line.split(':')for line in response.text.splitlines()) #The suffix of a SHA-1 hash . The number of times that password has appeared in breaches. ex: C6008F9CAB4083784CBD1874F76618D2A97:4567, suffix:count
        for h,count in hashes: #Iterates over all returned suffixes.Compares each with the user's hash suffix.
            #Means password was found in a breach that many times.
            if h == suffix:
                return int(count)
        return 0 #Password not found in any known breach.
    except Exception as e:
            return f"ERROR:{e}" #handles api connection issues effectively. If any error occurs during the process (e.g., network issue), it: Catches the exception
        
def on_key_release(event=None): #this is for ui callback. This function runs live whenever a user types something in the password entry field (<KeyRelease> event).
    password=password_entry.get() #Retrieves the current text entered by the user in the password field.
    if not password: #If the input is empty
        strength_label.config(text='Strength: ') # Clear the strength label
        suggestions_text.delete(0,tk.END) #Clear previous suggestions
        return #stop further processing 
    strength,suggestions,color=evaluate_password(password) # Analyze the password for strength
    pwned_count = check_pwned_password(password) ## Check if password is found in breaches using HIBP API
    
    if isinstance(pwned_count,int): # If breach count is successfully returned
        if pwned_count ==0:
            breach_info = "✅ Not found in known breaches" # Safe password
        else:
            breach_info = f"⚠️ Found {pwned_count} times in data breaches!"   # Warning: breached password
    else:
        breach_info = pwned_count # Show API error or exception message 
        
    strength_label.config(text=f'Strength: {strength}\n{breach_info}',fg=color)  # Display strength and breach info 
    suggestions_text.delete(0,tk.END) # Clear previous suggestions
    for sug in suggestions: # Loop through improvement suggestions
        suggestions_text.insert(tk.END,"• " + sug) #Add each as a bullet point in the listbox
    
#making the show or hide toggle for the password
def toggle_password():
    global show_password
    show_password = not show_password #toggle boolean flag ,0 or 1
    password = password_entry.get() #get the current password
    if show_password: #1
        password_entry.config(show='') #show the unmasked password
        toggle_btn.config(text='Hide') #update button label to hide
    else: #0
        password_entry.config(show="• ")  #show the masked password
        toggle_btn.config(text="Show") #update the button label to show 
        
def copy_to_clipboard():
    password = password_entry.get()
    window.clipboard_clear() #clearing the clipboard
    window.clipboard_append(password) #adding the password to the clipboard
    window.update() #updating the window
    copied_label.config(text="Copied ✅") #with this label copied 
    copied_label.after(2000,lambda: copied_label.config(text='')) #for the friendly gui the label copied gets vanished after 2000milliseconds

def clear_fields():
    password_entry.delete(0, tk.END) #delete the password entry box
    strength_label.config(text='Strength: ', fg='black') #the strength is earsed only the strength word is written
    suggestions_text.delete(0, tk.END) #suggestion box is earsed
    copied_label.config(text='') #clears the message of the label
    
#password generating
def generate_password():
    length =int(length_slider.get()) # Get the desired password length from the slider widget
    characters = string.ascii_letters + string.digits + string.punctuation #characters variables has all the string letters, digits and punctuations
    password=''.join(secrets.choice(characters)for _ in range(length)) #generating random password of the length selected from the bar 
    password_entry.delete(0,tk.END) #clearing the if any existing password on the password entry box
    password_entry.insert(0,password) #then inserting the new generated password 
    on_key_release() # Trigger password strength evaluation and breach check immediately

window =tk.Tk()
window.title("🔐 Password Strength Evaluator + Generator")
window.geometry("600x600")
window.configure(bg='#f2f2f2')
window.resizable(False, False)
show_password= False

title_label= tk.Label(window,text='Password Evaluator & Generator',font=('Times New Roman',18,'bold italic'),bg='#f2f2f2',fg='#333')
title_label.pack(pady=20)

entry_frame = tk.Frame(window,bg='#f2f2f2')
entry_frame.pack(pady=15)

tk.Label(entry_frame, text='Enter Password: ',font=("Segoe UI",12,'bold'),bg='#f2f2f2').grid(row=0,column=0,padx=5)
password_entry=tk.Entry(entry_frame, width=35,show='•',font=('Segoe Ui',11))
password_entry.grid(row=0,column=1)
password_entry.bind("<KeyRelease>",on_key_release)

btn_frame = tk.Frame(window, bg='#f2f2f2')
btn_frame.pack(pady=5)

toggle_btn = tk.Button(btn_frame, text='Show', command=toggle_password, width=8, font=('Segoe UI', 9), bg='#4da6ff', fg='white', activebackground='#007acc')
toggle_btn.pack(side=tk.LEFT, padx=5)

copy_btn = tk.Button(btn_frame, text='Copy', command=copy_to_clipboard, width=8, font=('Segoe UI', 9), bg='#ffaa00', fg='white', activebackground='#cc8400')
copy_btn.pack(side=tk.LEFT, padx=5)

clear_btn = tk.Button(btn_frame, text='Clear', command=clear_fields, width=8, font=('Segoe UI', 9), bg='#ff4d4d', fg='white', activebackground='#cc0000')
clear_btn.pack(side=tk.LEFT, padx=5)

copied_label = tk.Label(window,text='',font=('Segoe UI',9),bg='#f2f2f2',fg="green")
copied_label.pack()

strength_label= tk.Label(window,text='Strength: ',font=('Seogoe UI',12,'bold'))
strength_label.pack(pady=10)

tk.Label(window,text="Suggestions to Improve: ",font=('Segoe UI',12,'bold')).pack()
suggestions_text= tk.Listbox(window,width=60,height=6)
suggestions_text.pack(pady=5)

generator_frame=tk.Frame(window,bg='#f2f2f2')
generator_frame.pack(pady=10)

tk.Label(generator_frame,text='Generate Strong Password: ',font=('Segoe UI',11,'bold'),bg='#f2f2f2').grid(row=0,columnspan=2,pady=5)
tk.Label(generator_frame,text='Length: ').grid(row=1,column=0,padx=5)

#length_slider = tk.Scale(generator_frame,from_=8,to=32,orient='horizontal',length=200,bg='#f2f2f2')
length_slider = tk.Scale(
    generator_frame,
    from_=8,
    to=32,
    orient='horizontal',
    length=200,
    bg='#f2f2f2',              # background of widget
    fg='black',                # text color (not always visible on sliders)
    troughcolor='#d3d3d3',     # the bar's track color
    activebackground="#4CAF50",# color when actively sliding
    sliderrelief='raised',     # visual depth of the knob
    font=('Segoe UI', 10)
)
length_slider.set(12)
length_slider.grid(row=1,column=1)

generate_btn=tk.Button(generator_frame,text='Generate Password',command=generate_password,font=('Segoe UI',10),bg='#4CAF50', fg='white', activebackground='#388e3c')
generate_btn.grid(row=2,column=0,columnspan=2,pady=10)

window.mainloop()