from utils.encryption import decrypt_file

enc_file = input("Enter path to encrypted file: ")
key_file = input("Enter path to key file: ")
output_file = input("Enter path for decrypted output: ")

with open(enc_file, 'rb') as f:
    encrypted_data = f.read()
with open(key_file, 'rb') as f:
    key = f.read()

decrypted = decrypt_file(encrypted_data, key)

with open(output_file, 'wb') as f:
    f.write(decrypted)

print("Decryption complete! Output saved to", output_file)