from cryptography.fernet import Fernet

def generate_secret_key():
    """Generate a secret key"""
    key = Fernet.generate_key().decode()
    with open(".env", "w") as f:
        f.write(f'FERNET_KEY={key}')
