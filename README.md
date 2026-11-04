# NEXORA — Central pessoal de vendas digitais

Aplicativo privado **de uso individual** para organizar produtos, links de afiliado, interessados e respostas prontas.

## Estado atual
- ✅ Painel responsivo e instalável como PWA (com suporte do navegador).
- ✅ Catálogo manual com preço e link de produtos.
- ✅ Acompanhamento manual de interessados e status.
- ✅ Respostas prontas copiáveis.
- ✅ Links por campanha com contagem **apenas de aberturas realizadas neste navegador**.
- ✅ Exportação de backup JSON.
- ⏳ Direct, seguidores, curtidas, visualizações e demais insights oficiais: **ainda não conectados**. Dependem da API oficial da Meta e das permissões aplicáveis.
- ⏳ Autenticação real, banco Supabase e back-end seguro: **não implementados nesta versão**.

## Como experimentar
Abra `index.html` localmente ou publique um preview estático. A tela inicial identifica o modo de demonstração. Nenhuma informação é buscada do Instagram.

## Segurança
**Não publique o painel com dados reais ou sensíveis antes de configurar autenticação e RLS no backend.** O botão de entrada é apenas de demonstração, não é proteção de acesso. O uso de `localStorage` é limitado ao navegador e pode ser apagado pelo usuário; não sincroniza entre dispositivos.

O repositório está público. **Não faça commit de tokens, segredos Meta, credenciais Supabase service-role ou informações confidenciais de clientes.** Para produção recomendamos Supabase Auth, RLS, backend de webhooks/OAuth com verificação de assinatura, renovação segura de tokens, política de retenção e controles LGPD.

## Etapas seguintes
1. Login exclusivo de administrador por Supabase Auth, RLS e persistência segura.
2. Backend Meta OAuth e webhook, com credenciais fora do frontend.
3. Conexão da conta profissional e autorização de permissões para mensagens/insights.
4. Inbox real, envio de respostas autorizadas, métricas oficiais e analytics de campanhas com redirecionamento seguro.
5. Testes integrados, implantação e monitoramento.

**Observação:** a Meta limita métricas e mensagens acessíveis; ranking de interesse por produto deve ser gerado pelos eventos próprios rastreados e não confundido com insights nativos.
