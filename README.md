# Image Encryption & Decryption

This project provides a graphical user interface (GUI) for encrypting and decrypting messages hidden within images using the Least Significant Bit (LSB) technique and the `cryptography` library.

## Features

- **Encrypt and Embed Message**: Encrypt a message and embed it into an image.
- **Decrypt Message**: Decrypt a message hidden within an image.
- **Separate Windows**: Separate windows for encryption and decryption processes.

## Requirements

- Python 3.6+
- `Pillow` library
- `cryptography` library
- `tkinter` (usually included with Python)

## Installation

1. **Clone the Repository**:

   ```sh
   git clone https://github.com/mayur5204/Encrypting-messages-inside-an-image-using-LSB.git
   cd <repository-directory>
   ```

2. **Create a Virtual Environment**:

   ```sh
   python3 -m venv myenv
   source myenv/bin/activate  # On Windows use `myenv\Scripts\activate`
   ```

3. **Install Dependencies**:
   ```sh
   pip install pillow cryptography
   ```

## Running the Project

1. **Activate the Virtual Environment** (if not already activated):

   ```sh
   source myenv/bin/activate  # On Windows use `myenv\Scripts\activate`
   ```

2. **Run the Application**:
   ```sh
   python3 image_encrypt.py
   ```

## Usage

### Encrypt and Embed Message

1. Click on "Open Encryption Window".
2. Enter the password and the message to be encrypted.
3. Click on "Select Image for Encryption" to choose an image.
4. Click on "Encrypt and Embed Message" to encrypt the message and embed it into the selected image.
5. Save the new image with the embedded message.

### Decrypt Message

1. Click on "Open Decryption Window".
2. Enter the password.
3. Click on "Decrypt Message from Image" to choose an image with an embedded message.
4. The decrypted message will be displayed in a new window.

## Code Structure

- `image_encrypt.py`: Main application file containing the GUI and encryption/decryption logic.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Pillow](https://python-pillow.org/)
- [cryptography](https://cryptography.io/)
- [tkinter](https://docs.python.org/3/library/tkinter.html)
