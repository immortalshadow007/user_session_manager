import secrets

def generate_api_key(length=72):
    return secrets.token_urlsafe(length)

# Generate two 72-character-long API keys
api_key_1 = generate_api_key()
api_key_2 = generate_api_key()

print("API Key 1:", api_key_1)
print("API Key 2:", api_key_2)
