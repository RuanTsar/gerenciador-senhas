import requests

data = {
    "service": "gmail",
    "username": "meuemail@gmail.com",
    "password": "minhaSenha123"
}

response = requests.post("http://127.0.0.1:5000/save", json=data)

print("Status:", response.status_code)
print("Resposta:", response.json())
