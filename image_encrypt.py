import logging
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import tkinter as tk
from tkinter import filedialog, messagebox

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variables to hold the selected image path
selected_image_path = None

# Function to derive a key from the password
def derive_key(password: str) -> bytes:
    salt = b'some_salt'  # In a real application, use a unique salt for each password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Function to encrypt a message
def encrypt_message(message, key):
    f = Fernet(key)
    return f.encrypt(message.encode())

# Function to decrypt a message
def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()

# Function to hide encrypted data in image (using LSB technique)
def hide_data_in_image(image_path, data, output_image_path):
    logging.debug(f"Embedding data into image: {image_path}")
    img = Image.open(image_path)
    binary_data = ''.join(format(byte, '08b') for byte in data)
    binary_data += '1111111111111110'  # Add a delimiter to mark the end of the data
    data_index = 0
    img_data = list(img.getdata())
    
    for i in range(len(img_data)):
        pixel = list(img_data[i])
        for j in range(3):  # Iterate over RGB channels
            if data_index < len(binary_data):
                pixel[j] = int(bin(pixel[j])[:-1] + binary_data[data_index], 2)
                data_index += 1
        img_data[i] = tuple(pixel)
    
    img.putdata(img_data)
    img.save(output_image_path)
    logging.debug(f"Data embedded and image saved as: {output_image_path}")

# Function to extract binary data from image
def extract_data_from_image(image_path):
    logging.debug(f"Extracting data from image: {image_path}")
    img = Image.open(image_path)
    img_data = img.getdata()
    binary_data = ""
    
    for pixel in img_data:
        binary_data += bin(pixel[0])[-1]  # R
        binary_data += bin(pixel[1])[-1]  # G
        binary_data += bin(pixel[2])[-1]  # B
    
    all_bytes = [binary_data[i: i + 8] for i in range(0, len(binary_data), 8)]
    data = bytearray([int(byte, 2) for byte in all_bytes])
    
    # Find the delimiter and remove padding
    delimiter_index = data.find(b'\xff\xfe')
    if delimiter_index != -1:
        data = data[:delimiter_index]
    
    logging.debug(f"Data extracted: {data}")
    return bytes(data)  # Ensure the data is returned as bytes

# Function to encrypt the message and embed it in an image
def encrypt_and_embed():
    global selected_image_path
    if selected_image_path is None:
        messagebox.showerror("Error", "Please select an image to encrypt the message.")
        return
    
    message = message_entry.get("1.0", "end-1c")
    password = password_entry.get()
    
    if not message or not password:
        messagebox.showerror("Error", "Please enter both a message and password.")
        return
    
    key = derive_key(password)
    encrypted_message = encrypt_message(message, key)
    logging.debug(f"Message encrypted: {encrypted_message}")
    
    output_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if output_image_path:
        hide_data_in_image(selected_image_path, encrypted_message, output_image_path)
        messagebox.showinfo("Success", f"Message encrypted and saved in {output_image_path}")
        selected_image_path = None

# Function to decrypt message from an image
def decrypt_from_image():
    image_path = filedialog.askopenfilename(filetypes=[("PNG files", "*.png")])
    password = password_entry.get()
    
    if not image_path or not password:
        messagebox.showerror("Error", "Please select an image and enter the password.")
        return
    
    try:
        key = derive_key(password)
        encrypted_data = extract_data_from_image(image_path)
        logging.debug(f"Encrypted data extracted: {encrypted_data}")
        decrypted_message = decrypt_message(encrypted_data, key)
        logging.debug(f"Message decrypted: {decrypted_message}")
        show_decrypted_message(decrypted_message)
    except Exception as e:
        logging.error(f"Failed to decrypt message: {e}")
        messagebox.showerror("Error", "Failed to decrypt message or no hidden data found in the image.")

# Function to show the decrypted message in a new window
def show_decrypted_message(message):
    message_window = tk.Toplevel(root)
    message_window.title("Decrypted Message")
    message_window.geometry("600x400")

    text_widget = tk.Text(message_window, wrap=tk.WORD)
    text_widget.insert(tk.END, message)
    text_widget.pack(expand=True, fill=tk.BOTH)

    scrollbar = tk.Scrollbar(text_widget)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    text_widget.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=text_widget.yview)

# Function to select an image for encryption
def select_image():
    global selected_image_path
    selected_image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg")])
    if selected_image_path:
        image_label.config(text=f"Selected Image: {selected_image_path}")

# Function to open the encryption window
def open_encryption_window():
    encryption_window = tk.Toplevel(root)
    encryption_window.title("Encrypt and Embed Message")
    encryption_window.geometry("600x500")  # Increased size

    tk.Label(encryption_window, text="Encryption / Decryption Password:").pack(pady=10)
    global password_entry
    password_entry = tk.Entry(encryption_window, show="*", width=50)
    password_entry.pack(pady=5)

    tk.Label(encryption_window, text="Message to Encrypt:").pack(pady=10)
    global message_entry
    message_entry = tk.Text(encryption_window, height=5, width=50)
    message_entry.pack(pady=5)

    select_image_button = tk.Button(encryption_window, text="Select Image for Encryption", command=select_image)
    select_image_button.pack(pady=10)

    encrypt_button = tk.Button(encryption_window, text="Encrypt and Embed Message", command=encrypt_and_embed)
    encrypt_button.pack(pady=10)

    global image_label
    image_label = tk.Label(encryption_window, text="No image selected.")
    image_label.pack(pady=10)

# Function to open the decryption window
def open_decryption_window():
    decryption_window = tk.Toplevel(root)
    decryption_window.title("Decrypt Message from Image")
    decryption_window.geometry("600x300")  # Increased size

    tk.Label(decryption_window, text="Decryption Password:").pack(pady=10)
    global password_entry
    password_entry = tk.Entry(decryption_window, show="*", width=50)
    password_entry.pack(pady=5)

    decrypt_button = tk.Button(decryption_window, text="Decrypt Message from Image", command=decrypt_from_image)
    decrypt_button.pack(pady=10)

# Main window setup
root = tk.Tk()
root.title("Image Encryption & Decryption")
root.geometry("400x300")  # Increased size

# Buttons to open encryption and decryption windows
encryption_window_button = tk.Button(root, text="Open Encryption Window", command=open_encryption_window)
encryption_window_button.pack(pady=10)

decryption_window_button = tk.Button(root, text="Open Decryption Window", command=open_decryption_window)
decryption_window_button.pack(pady=10)

root.mainloop()
