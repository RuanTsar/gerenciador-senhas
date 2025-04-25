from auth import hash_password

def init_master_password():
    try:
        with open(".master_pwd", "x") as f:
            senha = input("Defina a senha mestra: ")
            f.write(hash_password(senha))
            print("Senha mestra salva com sucesso!")
    except FileExistsError:
        print("Senha mestra já foi definida.")

if __name__ == "__main__":
    init_master_password()
