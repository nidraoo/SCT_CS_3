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
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix,suffix = sha1[:5],sha1[5:]
    try:
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
        if response.status_code != 200:
            return 'API ERROR'
        hashes =(line.split(':')for line in response.text.splitlines())
        for h,count in hashes:
            if h == suffix:
                return int(count)
        return 0
    except Exception as e:
            return f"ERROR:{e}"
        
def on_key_release(event=None): #this is for ui callback
    password=password_entry.get()
    if not password:
        strength_label.config(text='Strength: ')
        suggestions_text.delete(0,tk.END)
        return 
    strength,suggestions,color=evaluate_password(password)
    pwned_count = check_pwned_password(password) 
    
    if isinstance(pwned_count,int):
        if pwned_count ==0:
            breach_info = "✅ Not found in known breaches"
        else:
            breach_info = f"⚠️ Found {pwned_count} times in data breaches!"   
    else:
        breach_info = pwned_count
        
    strength_label.config(text=f'Strength: {strength}\n{breach_info}',fg=color)  
    suggestions_text.delete(0,tk.END)
    for sug in suggestions:
        suggestions_text.insert(tk.END,"• " + sug)
    
#making the show or hide toggle for the password
def toggle_password():
    global show_password
    show_password = not show_password
    password = password_entry.get()
    if show_password:
        password_entry.config(show='')
        toggle_btn.config(text='Hide')
    else:
        password_entry.config(show="• ") 
        toggle_btn.config(text="Show")
        
def copy_to_clipboard():
    password = password_entry.get()
    window.clipboard_clear()
    window.clipboard_append(password)
    window.update()
    copied_label.config(text="Copied ✅")
    copied_label.after(2000,lambda: copied_label.config(text=''))

def clear_fields():
    password_entry.delete(0, tk.END)
    strength_label.config(text='Strength: ', fg='black')
    suggestions_text.delete(0, tk.END)
    copied_label.config(text='')
    
#password generating
def generate_password():
    length =int(length_slider.get())
    characters = string.ascii_letters + string.digits + string.punctuation
    password=''.join(secrets.choice(characters)for _ in range(length))
    password_entry.delete(0,tk.END)
    password_entry.insert(0,password)
    on_key_release()

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