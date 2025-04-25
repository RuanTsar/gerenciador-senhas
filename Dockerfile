# Usa imagem base leve com Python 3.9
FROM python:3.9-slim

# Variáveis de ambiente
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DEFAULT_TIMEOUT=100

# Instala dependências do sistema
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    netcat-openbsd \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Define diretório de trabalho
WORKDIR /app

# Copia arquivos necessários antes da instalação
COPY requirements.txt .

# Instala pacotes Python usando mirror alternativo (USTC)
RUN pip install --no-cache-dir -i https://pypi.mirrors.ustc.edu.cn/simple -r requirements.txt

# Copia todo o restante da aplicação
COPY . .

# Cria o diretório de logs
RUN mkdir -p logs

# Torna o script `wait-for-it.sh` executável
RUN chmod +x /app/wait-for-it.sh

# Define variáveis de ambiente
ENV FLASK_APP=app.py
ENV FLASK_ENV=development

# Expõe a porta 5000
EXPOSE 5000

# Comando padrão — será sobrescrito pelo docker-compose, se necessário
CMD ["./wait-for-it.sh", "db:5432", "--", "python", "app.py"]
