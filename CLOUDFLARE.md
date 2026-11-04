# Cloudflare backend — instalação

Esta branch contém a **base** de um backend privado no Cloudflare Workers e D1. **Não foi implantado**; não existe conta Cloudflare conectada a este chat.

## Instalação
1. Entre na sua conta Cloudflare e crie um banco D1 chamado `instagram-sales-hub`.
2. Copie o ID real do D1 para `wrangler.toml` no lugar de `REPLACE_WITH_D1_DATABASE_ID`.
3. Instale o Wrangler, autentique-se com `npx wrangler login` e aplique o SQL: `npx wrangler d1 execute instagram-sales-hub --remote --file=./migrations/0001_initial.sql`.
4. Configure um segredo longo e aleatório com `npx wrangler secret put ADMIN_TOKEN` (não faça commit do valor).
5. Publique com `npx wrangler deploy`. Teste `/health` e requisições autenticadas à API.
6. Configure os segredos `META_VERIFY_TOKEN` e `META_APP_SECRET` **somente quando configurar a aplicação Meta**.

## API
- `GET /health` público, sem dados privados
- `GET /api/products|leads|replies|campaigns` exige `Authorization: Bearer <ADMIN_TOKEN>`
- `POST /api/...` cria registros, `DELETE /api/.../:id` exclui
- `GET /webhooks/instagram` valida o challenge da Meta
- `POST /webhooks/instagram` verifica assinatura HMAC e armazena eventos brutos

## Limitações e segurança
O painel HTML atual **ainda usa localStorage**, não esta API. Não cole o token de administrador no frontend estático. Antes de conectar o painel, implemente sessão via Cloudflare Access ou autenticação com cookies HttpOnly e verificação no Worker. Não habilite CORS amplo. A API de Direct real e os insights oficiais ainda não foram implementados. Webhooks brutos exigem retenção limitada, processamento seguro, deduplicação e tratamento de dados pessoais antes do uso em produção.

A integração Meta depende de permissões oficiais. Este código não contorna regras da plataforma. Não envie mensagens automáticas não solicitadas.
