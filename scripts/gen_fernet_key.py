"""Gera uma chave Fernet (URL-safe base64 32B) pra usar em FERNET_KEY."""
from cryptography.fernet import Fernet

print(Fernet.generate_key().decode())
