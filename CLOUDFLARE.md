# Sales Hub — Cloudflare Workers, Access e Instagram

## Estrutura atual
- Worker: `instagram-sales-hub`
- Endereço público: https://instagram-sales-hub.lucaalves17-20.workers.dev
- Banco D1: `instagram-sales-hub-db`
- Branch de produção: `feat/personal-sales-dashboard`
- Instagram autorizado na Meta: `@advisory.ofc`
- Aplicativo Meta: `Sales Hub`
- A aplicação administrativa permanece protegida pelo Cloudflare Access.

## Configuração versionada no Git
O arquivo `wrangler.toml` possui o binding D1, os assets e as variáveis **não secretas** de autenticação: `ACCESS_AUD`, `ACCESS_TEAM_DOMAIN` e `ADMIN_EMAIL`. A opção `keep_vars = true` preserva variáveis configuradas no dashboard quando o Wrangler publicar uma versão.

**Nunca inserir valores de tokens/chaves no Git.** Configurar diretamente em **Workers & Pages → instagram-sales-hub → Settings → Variables and Secrets → Secret**:
- `META_ACCESS_TOKEN`: token oficial da conta Instagram emitido pela Meta;
- `META_VERIFY_TOKEN`: segredo escolhido para o desafio de verificação do webhook;
- `META_APP_SECRET`: chave secreta do app Meta usada para validar a assinatura HMAC das requisições;
- `ADMIN_TOKEN` (opcional): compatibilidade com acesso administrativo por bearer token. Cloudflare Access é a forma principal.

Após editar segredos, publicar a versão em **Production**. Nunca postar valores no chat, no repositório ou no frontend.

## Webhook
- URL de callback: `https://instagram-sales-hub.lucaalves17-20.workers.dev/webhooks/instagram`
- Campo Verify Token na Meta: **o mesmo valor** configurado em `META_VERIFY_TOKEN`.
- Webhooks assinados: `messages` e `messaging_postbacks` (se habilitados na Meta).
- `GET /webhooks/instagram`: com token configurado, devolve `invalid_challenge` (403) se acessado sem parâmetros, ou o challenge em uma verificação correta da Meta.
- `POST /webhooks/instagram`: exige assinatura `x-hub-signature-256` válida usando `META_APP_SECRET` e grava o JSON bruto em `webhook_events` no D1.
- A exceção pública do Cloudflare Access deve cobrir **somente** `/webhooks/instagram`. Verifique que o restante do painel requer login.

## API do painel
- `GET /health`: saúde do Worker e binding do D1 (não expõe segredos).
- `GET /api/integration/status`: exige autenticação no Worker; informa presença dos segredos do webhook, disponibilidade do token e quantidade/data de eventos.
- `GET /api/messages/recent`: exige autenticação; lê os últimos 250 eventos armazenados, extrai mensagens de `object: instagram`, remove duplicatas por ID, ignora mensagens de saída (`is_echo`) e devolve no máximo 50 mensagens de entrada reais.
- O painel não busca nomes de usuários nem executa chamadas ao Graph API com `META_ACCESS_TOKEN`; o token presente não significa que tenha sido validado contra a Meta.
- A indicação de origem de anúncio depende de metadados `ads_context_data` ou `referral` realmente recebidos, e não permite inferir origem quando a Meta não os envia.
- Não há cadastro manual de produtos, campanhas, interessados ou respostas.

## Verificação funcional
1. Confirmar os segredos na área **Runtime / Variables and Secrets** do Worker.
2. Abrir `/webhooks/instagram` no navegador: `{"error":"invalid_challenge"}` indica que o token de verificação foi carregado (a validação real é feita pela Meta).
3. No Meta Developers, verificar a inscrição do campo `messages`.
4. Enviar uma DM de outra conta que seja elegível/autorizada para testes enquanto o app estiver em modo de desenvolvimento.
5. Checar `Eventos de webhook recebidos` e a seção `Mensagens recentes` no painel, com login Cloudflare Access.
6. Se o contador permanecer zero, checar entrega dos webhooks, assinatura HMAC e logs do Worker antes de modificar o banco.

## Limitações atuais
- Webhooks foram autorizados/configurados pelo usuário, mas não foi confirmado ainda o recebimento de uma mensagem real no D1.
- Eventos antigos podem repetir registros por retentativas da Meta; a leitura faz deduplicação apenas para apresentação.
- A lista exibe até 50 mensagens contidas nos últimos 250 eventos; **não** é um histórico completo.
- Implementar política de retenção/expurgo dos eventos brutos e controles de privacidade antes de uso continuado em produção.
- Permissões avançadas e análise do app pela Meta podem ser exigidas para mensagens de contas não participantes do teste.
