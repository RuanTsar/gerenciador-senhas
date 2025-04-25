from crypto import generate_key, save_key

key = generate_key()
save_key(key)

print("Chave secreta criada e salva em 'secret.key'.")
