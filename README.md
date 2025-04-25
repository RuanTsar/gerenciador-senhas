# Password Manager

A secure web application for managing your passwords, built with Flask and PostgreSQL.

## Features

- Secure password storage with encryption
- User authentication and authorization
- Password strength validation
- Secure password generation
- Audit logging
- Rate limiting for security

## Prerequisites

- Python 3.9+
- Docker and Docker Compose (for local development)
- PostgreSQL (handled by Docker for local development)

## Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/gerenciador-senhas.git
   cd gerenciador-senhas
   ```

2. Create a `.env` file:
   ```bash
   cp .env.example .env
   ```
   Edit the `.env` file with your local configuration.

3. Start the application:
   ```bash
   docker-compose up
   ```

4. Access the application:
   - Web interface: http://localhost:5000
   - PgAdmin: http://localhost:5050 (admin@admin.com / admin123)

## Deployment on Render

1. Create a new Web Service on Render
2. Connect your GitHub repository
3. Configure the following environment variables:
   - `POSTGRES_DB`
   - `POSTGRES_USER`
   - `POSTGRES_PASSWORD`
   - `POSTGRES_HOST`
   - `POSTGRES_PORT`
   - `SECRET_KEY`
   - `DEBUG` (set to False for production)
   - `SESSION_COOKIE_SECURE` (set to True for production)

4. Deploy!

## Project Structure

```
.
├── app.py              # Main application file
├── config.py           # Configuration settings
├── models.py           # Database models
├── security.py         # Security functions
├── forms.py            # Form definitions
├── crypto.py           # Encryption functions
├── requirements.txt    # Python dependencies
├── Dockerfile          # Docker configuration
├── docker-compose.yml  # Docker Compose configuration
├── render.yaml         # Render deployment configuration
└── templates/          # HTML templates
```

## Security Features

- Password encryption
- Rate limiting
- Session security
- Password strength validation
- Audit logging
- CSRF protection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 