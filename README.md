# LKGERENCIAMENTO — versão online com banco de dados

## Stack
- Node.js + Express
- SQLite (arquivo local no servidor)
- bcrypt para senhas
- JWT em cookie HttpOnly
- Helmet
- Rate limiting
- API com autorização por perfil

## Rodar localmente
1. Instale Node.js 20+.
2. Copie `.env.example` para `.env`.
3. Defina `JWT_SECRET` com uma chave aleatória grande.
4. Defina `ADMIN_PASSWORD` com uma senha forte.
5. Execute:
   npm install
   npm start
6. Abra http://localhost:3000

O banco é criado automaticamente em `data/lkgerenciamento.db`.

## Primeiro acesso
O administrador geral é criado automaticamente usando ADMIN_EMAIL e ADMIN_PASSWORD.

## Regras
- ADMIN vê toda a rede.
- SUBADMIN vê apenas seus próprios cadastros.
- CAD e matrícula são únicos em toda a base.
- Novo cadastro entra como "EM_ANALISE".
- Somente ADMIN pode efetivar ou rejeitar.
- O sistema grava histórico das ações.
- A exclusão de subadministrador não apaga automaticamente os cadastros dele.

## Publicação
Para colocar em produção:
- use HTTPS;
- defina COOKIE_SECURE=true;
- mantenha JWT_SECRET fora do código;
- faça backups do diretório `data/`;
- coloque a aplicação atrás de um proxy HTTPS (Nginx/Cloudflare ou equivalente);
- use um domínio próprio.

Esta entrega é um projeto funcional de backend + frontend. Ela não cria hospedagem, domínio ou banco externo automaticamente; esses itens dependem do provedor escolhido.
