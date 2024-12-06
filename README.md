# Password Vault

### A Custom, Hacker-Style Terminal-Based Password Manager

Welcome to **Password Vault**, a simple yet secure command-line password manager built in Python. This tool lets you store, retrieve, and update login credentials for various websites and services, all encrypted on disk. It’s perfect for programmers, hackers, and command-line enthusiasts who appreciate a clean, modern terminal aesthetic.

---

## Features

- **Terminal-Based Interface**: No bulky GUI—just run it in your favorite terminal for a sleek, hacker-like feel.
- **Encrypted Data Storage**: Your passwords are encrypted at rest using Python’s `cryptography` library and a master password.
- **Simple to Use**: Add, view, and update accounts through a straightforward menu.
- **Customizable**: Easily modify the Python code to add more features or integrate with your workflow.

---

## Requirements

- **Python 3.x** installed on your system.
- `cryptography` Python library.
- A Linux environment (developed and tested on Pop!_OS).
- `nvim` (Neovim) or any other text editor if you want to tweak the code.

---

## Installation & Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/theRadicalSoftware/password-vault.git
   cd password-vault
Create and Activate a Virtual Environment (optional but recommended):

bash
Copy code
python3 -m venv venv
source venv/bin/activate
Install Dependencies:

bash
Copy code
pip install cryptography
Run the Vault:

bash
Copy code
python vault.py
The first time you run it, you’ll be asked for a master password. If no vault exists, it will create one.

Usage
When Running the Vault, you’ll see a menu like this:

[1] Add Account
[2] View Accounts
[3] Update Account
[q] Quit
Add Account: Enter site/service name, username, password, and optional notes.
View Accounts: Displays all stored accounts and their credentials.
Update Account: Modify site, username, password, or notes of an existing entry.
Quit: Exit the vault.

All data is encrypted on disk, so you need your master password each time to unlock and view/edit your data.

Security Notes
Master Password: Choose a strong master password. The encryption key is derived from this password.
Encryption: Currently uses Fernet symmetric encryption from cryptography. For stronger security, consider using a proper KDF with salt and PBKDF2HMAC.
Don’t Commit Secrets: By default, vault_data.enc is listed in .gitignore. Keep your secret data local to avoid accidental commits.
Customization
Feel free to open vault.py in nvim (or any editor) to:

Change colors or ASCII banners.
Add searching/filtering functionality.
Implement more robust encryption practices.
Integrate with other command-line tools or scripts.
Contributing
Contributions, suggestions, and improvements are welcome! Just open an issue or submit a pull request on GitHub.

License
This project is distributed under the MIT License. See LICENSE for more details.
