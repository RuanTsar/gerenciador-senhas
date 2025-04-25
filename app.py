from db import init_db as db_init  # para não conflitar
from flask import Flask, request, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from auth import verify_password, hash_password
from db import save_password, delete_password, update_password, get_db_connection
from crypto import load_key, encrypt_password, decrypt_password
import os

os.environ["POSTGRES_DB"] = "gerenciador"
os.environ["POSTGRES_USER"] = "usuario"
os.environ["POSTGRES_PASSWORD"] = "senha123"


db_init()  # esse é o init que você quer executar de verdade
# Inicializa o banco de dados (cria as tabelas)


app = Flask(__name__)
app.secret_key = "chave_super_secreta"

key = load_key()
@app.route("/")
def home():
    return redirect(url_for("login"))

# ====================
# ROTA: Salvar nova senha
# ====================
@app.route("/save", methods=["POST"])
def save():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    service = request.form["service"]
    username = request.form["username"]
    password = request.form["password"]
    encrypted = encrypt_password(password, key)

    save_password(service, username, encrypted, session["user_id"])
    return redirect(url_for("dashboard"))

# ====================
# ROTA: Sessão e Acesso Individual
# ====================
@app.route('/dashboard')
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor()

    # Busca as senhas do usuário logado
    cur.execute("SELECT id, service, username, password FROM passwords WHERE user_id = %s", (user_id,))
    registros = cur.fetchall()

    cur.close()
    conn.close()

    # Descriptografa as senhas
    senhas = [
        {
            "id": id,
            "service": service,
            "username": username,
            "password": decrypt_password(encrypted_password, key)
        }
        for id, service, username, encrypted_password in registros
    ]

    return render_template("dashboard.html", senhas=senhas)




# ====================
# ROTA: Deletar senha
# ====================
@app.route('/delete/<int:id>', methods=["POST"])
def delete(id):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    delete_password(id, session["user_id"])
    return redirect(url_for('dashboard'))

# ====================
# ROTA: Editar senha
# ====================
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        service = request.form['service']
        username = request.form['username']
        password = request.form['password']
        encrypted = encrypt_password(password, key)

        update_password(id, service, username, encrypted, session["user_id"])
        return redirect(url_for('dashboard'))

    cursor.execute('SELECT service, username, password FROM passwords WHERE id = %s AND user_id = %s', (id, session["user_id"]))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return "Entrada não encontrada", 404

    service, username, encrypted_password = row
    decrypted = decrypt_password(encrypted_password, key)

    return render_template('edit.html', service=service, username=username, password=decrypted, id=id)

# ====================
# ROTA: Login de usuários
# ====================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print("Tentativa de login:")
        print("Usuário digitado:", username)
        print("Senha digitada:", password)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, hashed_password FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        print("Resultado da query:", user)

        if user:
            user_id, hashed_password = user
            print("Hash no banco:", hashed_password)

            senha_ok = check_password_hash(hashed_password, password)
            print("Senha confere?", senha_ok)

            if senha_ok:
                session['user_id'] = user_id
                print("Login bem-sucedido. Redirecionando para dashboard.")
                return redirect(url_for("dashboard"))
            else:
                print("Senha incorreta.")
        else:
            print("Usuário não encontrado.")

        return render_template("login.html", erro="Credenciais inválidas.")

    return render_template('login.html')


# ====================
# ROTA: Logout
# ====================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ====================
# ROTA: Alterar senha mestra
# ====================
@app.route("/change_master_password", methods=["GET", "POST"])
def change_master_password():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    if request.method == "POST":
        senha_atual = request.form["senha_atual"]
        nova_senha = request.form["nova_senha"]

        with open(".master_pwd") as f:
            hash_salvo = f.read()

        if verify_password(hash_salvo, senha_atual):
            with open(".master_pwd", "w") as f:
                f.write(hash_password(nova_senha))
            return redirect(url_for("dashboard"))
        else:
            return render_template("change_master_password.html", erro="Senha atual incorreta.")
    
    return render_template("change_master_password.html")

# ====================
# ROTA: Registro de novo usuário
# ====================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute("""
                INSERT INTO users (username, email, hashed_password)
                VALUES (%s, %s, %s)
            """, (username, email, hashed_password))
            conn.commit()
        except Exception as e:
            conn.rollback()
            return f"Erro ao registrar usuário: {str(e)}", 400

        cur.close()
        conn.close()
        return redirect('/login')

    return render_template('register.html')

# ====================
# Início da aplicação
# ====================
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
