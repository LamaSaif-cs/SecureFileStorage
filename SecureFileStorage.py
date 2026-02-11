from tkinter import *
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
import os
import hashlib
# ------------------------- AES Functions --------------------------
AES_KEY = b"MySecretAESKey12"
def pad(data):
    return data + b"\0" * (AES.block_size - len(data) % AES.block_size)


def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()


def encrypt_file(file_path, output_folder, key):
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext))
    filename = os.path.basename(file_path)
    output_path = os.path.join(output_folder, filename + ".enc")
    with open(output_path, 'wb') as f:
        f.write(ciphertext)
    return output_path

def decrypt_file(file_path, output_folder, key):
    with open(file_path, 'rb') as f:
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext).rstrip(b"\0")
    filename = os.path.basename(file_path).replace(".enc", "")
    output_path = os.path.join(output_folder, filename)
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    return output_path

# ------------------------- User Authentication --------------------------
def load_users():
    users = {}
    if os.path.exists("users.txt"):
        with open("users.txt", "r") as f:
            for line in f:
                username,  password_hash = line.strip().split(",")
                users[username] =  password_hash
    return users

def save_user(username, password):
    hashed = hash_password(password)
    with open("users.txt", "a") as f:
        f.write(f"{username},{hashed}\n")

# ------------------------- GUI --------------------------
root = Tk()
root.title('Authentication')
root.geometry("400x300+500+300")

# -------------------- Login Window --------------------
def login_action(username_entry, password_entry):
    users = load_users()
    username = username_entry.get()
    password = password_entry.get()
    if username in users and users[username] == hash_password(password):
        messagebox.showinfo("Login", "Login Successful")
        EncryptionWindow()
    else:
        messagebox.showerror("Login", "Invalid Username or Password")

def LoginWindow():
    for widget in root.winfo_children():
        widget.destroy()

    root.rowconfigure([0,1,2], weight=1)
    root.columnconfigure([0,1], weight=1)

    Label(root, text='UserName:').grid(row=0, column=0, sticky=E)
    username_entry = Entry(root)
    username_entry.grid(row=0, column=1)

    Label(root, text='Password:').grid(row=1, column=0, sticky=E)
    password_entry = Entry(root, show='*')
    password_entry.grid(row=1, column=1)

    Button(root, text="Login", command=lambda: login_action(username_entry, password_entry)).grid(row=2, column=0, padx=5, pady=5)
    Button(root, text="Sign Up", command=SigninWindow).grid(row=2, column=1, padx=5, pady=5)
    Button(root, text="Exit", command=root.destroy, bg="red", fg="white").grid(row=3, column=0, columnspan=2, pady=10)

# -------------------- Sign Up Window --------------------
def SigninWindow():
    sign = Toplevel(root)
    sign.title("Sign Up")
    sign.geometry('300x200+550+350')

    sign.rowconfigure([0,1,2,3], weight=1)
    sign.columnconfigure([0,1], weight=1)

    Label(sign, text='UserName:').grid(row=0, column=0, sticky=E, padx=5, pady=5)
    username_entry = Entry(sign)
    username_entry.grid(row=0, column=1, padx=5, pady=5)

    Label(sign, text='Password:').grid(row=1, column=0, sticky=E, padx=5, pady=5)
    password_entry = Entry(sign, show='*')
    password_entry.grid(row=1, column=1, padx=5, pady=5)

    def signup_action():
        username = username_entry.get()
        password = password_entry.get()
        if username and password:
            save_user(username, password)
            messagebox.showinfo("Sign Up", "User Registered Successfully")
            sign.destroy()
        else:
            messagebox.showerror("Sign Up", "Please fill all fields")

    Button(sign, text="Sign Up", command=signup_action, width=15).grid(row=2, column=0, columnspan=2, pady=10)
    Button(sign, text="Back", command=sign.destroy, width=15, bg="gray", fg="white").grid(row=3, column=0, columnspan=2, pady=5)


# -------------------- Encryption Window --------------------
def EncryptionWindow():
    win = Toplevel(root)
    win.title("File Encryption Tool")
    win.geometry("700x450+400+200")
    win.resizable(False, False)
    frame = Frame(win)
    frame.place(relx=0.5, rely=0.05, anchor=N)

    Label(frame, text="Select File:").grid(row=0, column=0)
    file_path_var = StringVar()
    Entry(frame, textvariable=file_path_var, width=50).grid(row=0, column=1)

    def choose_file():
        path = filedialog.askopenfilename()
        if path:
            file_path_var.set(path)
            log_listbox.insert(END, f"Selected file: {path}")

    Button(frame, text="Choose File", command=choose_file).grid(row=0, column=2)

    Label(frame, text="Output Folder:").grid(row=1, column=0)
    output_folder_var = StringVar()
    Entry(frame, textvariable=output_folder_var, width=50).grid(row=1, column=1)

    def choose_output_folder():
        folder = filedialog.askdirectory()
        if folder:
            output_folder_var.set(folder)
            log_listbox.insert(END, f"Output folder: {folder}")

    Button(frame, text="Browse", command=choose_output_folder).grid(row=1, column=2)


    # Buttons
    def encrypt_action():
        try:
            file_path = file_path_var.get()
            output_folder = output_folder_var.get()
            key = AES_KEY
            out_file = encrypt_file(file_path, output_folder, key)
            log_listbox.insert(END, f"Encrypted: {out_file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_action():
        try:
            file_path = file_path_var.get()
            output_folder = output_folder_var.get()
            key = AES_KEY
            out_file = decrypt_file(file_path, output_folder, key)
            log_listbox.insert(END, f"Decrypted: {out_file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    buttons_frame = Frame(win)
    buttons_frame.place(relx=0.5, rely=0.25, anchor=N)
    Button(buttons_frame, text="Encrypt", command=encrypt_action, bg="green", fg="white", width=15).grid(row=0, column=0, padx=10)
    Button(buttons_frame, text="Decrypt", command=decrypt_action, bg="blue", fg="white", width=15).grid(row=0, column=1, padx=10)
    Button(buttons_frame, text="Back", command=win.destroy, bg="gray", fg="white", width=15).grid(row=0, column=2, padx=10)

    # Log
    log_frame = Frame(win)
    log_frame.place(relx=0.5, rely=0.4, anchor=N)
    scrollbar = Scrollbar(log_frame)
    scrollbar.pack(side=RIGHT, fill=Y)
    log_listbox = Listbox(log_frame, width=80, height=15, yscrollcommand=scrollbar.set)
    log_listbox.pack(side=LEFT)
    scrollbar.config(command=log_listbox.yview)
    log_listbox.insert(END, "Ready. Choose a file and encrypt/decrypt.")


LoginWindow()
root.mainloop()
