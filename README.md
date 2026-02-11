This project is a file encryption and decryption tool using the AES algorithm, combined with a user authentication system to secure access. 
Users can select files and folders and protect their data securely.

The project features an easy-to-use GUI built with Tkinter, allowing users to:
Create a new account (Sign Up) and log in (Login).
Choose files from their computer to encrypt or decrypt.
Select the output folder to save encrypted or decrypted files.
View a log of all operations directly in the interface, showing which files were successfully encrypted or decrypted.

Features:
File encryption using AES-128 in ECB mode.
Secure password storage using SHA-256 hashing.
Simple and user-friendly graphical interface.
Option to select any file and output folder.
Real-time operation log.

Technologies & Libraries Used:
Python 3.x – main programming language.
Tkinter – for creating the GUI.
PyCrypto / Crypto – for file encryption and decryption with AES.
hashlib – for secure password hashing.
os – for file and folder management.
