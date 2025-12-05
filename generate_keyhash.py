import hashlib

api_key = input("Enter your API key: ")
hash_object = hashlib.sha256(api_key.encode())
api_key_hash = hash_object.hexdigest()
print(api_key_hash)
