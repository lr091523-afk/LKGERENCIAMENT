# LKGERENCIAMENTO v3 — PostgreSQL

Versão preparada para PostgreSQL gerenciado.

## Render
Build Command: npm install
Start Command: npm start
Root Directory: vazio
Branch: main

Environment Variables:
- DATABASE_URL = Internal Database URL do PostgreSQL da Render
- JWT_SECRET = chave longa e aleatória
- ADMIN_EMAIL = seu e-mail
- ADMIN_PASSWORD = senha forte
- COOKIE_SECURE = true

O servidor cria as tabelas automaticamente na primeira inicialização.

Nunca publique senhas reais ou DATABASE_URL no GitHub.
