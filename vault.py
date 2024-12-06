import json
import os
import getpass
from cryptography.fernet import Fernet

# Global constants for file paths
VAULT_FILE = "vault_data.enc"
SALT_FILE = "vault_salt.bin"

def main():
    print("=== Welcome to Your Custom Hacker-Style Password Vault ===")
    # Prompt for master password
    master_password = getpass.getpass("Enter master password: ")

    # Derive encryption key from master password
    key = derive_key(master_password)

    # Check if vault exists; if not, initialize
    if not os.path.exists(VAULT_FILE):
        print("No existing vault found. Initializing a new one...")
        initialize_vault(key)

    # Load and decrypt vault data
    vault_data = load_vault(key)

    while True:
        print_menu()
        choice = input("Select an option: ").strip().lower()
        if choice == '1':
            add_account(vault_data)
            save_vault(key, vault_data)
        elif choice == '2':
            view_accounts(vault_data)
        elif choice == '3':
            update_account(vault_data)
            save_vault(key, vault_data)
        elif choice == 'q':
            print("Exiting vault. Stay safe out there.")
            break
        else:
            print("Invalid option. Try again.")

def print_menu():
    print("\n--- Main Menu ---")
    print("[1] Add Account")
    print("[2] View Accounts")
    print("[3] Update Account")
    print("[q] Quit")

def derive_key(password: str) -> bytes:
    # For simplicity, let's do a very basic key derivation using a Fernet key.
    # NOTE: This is not the most secure KDF usage, but it's simpler for a demo.
    # A real KDF example would use PBKDF2HMAC or similar from cryptography.
    # We'll improve this in a moment.
    from cryptography.fernet import Fernet
    # Warning: This is a demo. In a real scenario, use a proper KDF!
    # Let's just generate a key from the password by hashing it (quick & dirty).
    import hashlib
    digest = hashlib.sha256(password.encode()).digest()
    # Fernet keys must be 32 bytes in url-safe base64
    # We'll just take our digest and base64 encode it
    import base64
    key = base64.urlsafe_b64encode(digest)
    return key

def initialize_vault(key: bytes):
    empty_data = {"accounts": []}
    save_vault(key, empty_data)

def load_vault(key: bytes) -> dict:
    with open(VAULT_FILE, "rb") as f:
        encrypted_data = f.read()
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data)
    return json.loads(decrypted.decode("utf-8"))

def save_vault(key: bytes, data: dict):
    fernet = Fernet(key)
    json_data = json.dumps(data).encode("utf-8")
    encrypted_data = fernet.encrypt(json_data)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted_data)

def add_account(vault_data: dict):
    site = input("Site/Service name: ")
    username = input("Username: ")
    password = input("Password: ")
    notes = input("Notes (optional): ")
    vault_data["accounts"].append({
        "site": site,
        "username": username,
        "password": password,
        "notes": notes
    })
    print("Account added successfully!")

def view_accounts(vault_data: dict):
    if not vault_data["accounts"]:
        print("No accounts stored.")
        return
    for i, account in enumerate(vault_data["accounts"], start=1):
        print(f"{i}. {account['site']} - {account['username']} - {account['password']}")

def update_account(vault_data: dict):
    if not vault_data["accounts"]:
        print("No accounts to update.")
        return
    # List accounts
    for i, account in enumerate(vault_data["accounts"], start=1):
        print(f"{i}. {account['site']} - {account['username']}")
    choice = input("Enter number of account to update: ")
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(vault_data["accounts"]):
            print("Invalid choice.")
            return
    except ValueError:
        print("Invalid input.")
        return
    acc = vault_data["accounts"][idx]

    print(f"Current site: {acc['site']}")
    new_site = input("New site (leave blank to keep current): ")
    if new_site.strip():
        acc['site'] = new_site.strip()

    print(f"Current username: {acc['username']}")
    new_user = input("New username (leave blank to keep current): ")
    if new_user.strip():
        acc['username'] = new_user.strip()

    print(f"Current password: {acc['password']}")
    new_pass = input("New password (leave blank to keep current): ")
    if new_pass.strip():
        acc['password'] = new_pass.strip()

    print(f"Current notes: {acc['notes']}")
    new_notes = input("New notes (leave blank to keep current): ")
    if new_notes.strip():
        acc['notes'] = new_notes.strip()

    print("Account updated successfully!")

if __name__ == "__main__":
    main()

