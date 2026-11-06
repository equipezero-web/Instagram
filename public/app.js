document.addEventListener("DOMContentLoaded",async()=>{
  const byId=id=>document.getElementById(id);
  const status=byId("status"),notice=byId("notice"),meta=byId("meta-status");

  const detail=byId("integration-detail");
  const checkButton=byId("check-meta");
  const subscribeButton=byId("subscribe-meta");
  const refreshButton=byId("refresh-messages");
  let accountConfirmed=false;
  async function verifyMeta(){
    checkButton.disabled=true;
    detail.textContent="Consultando conta e assinatura pela API oficial da Meta...";
    try{
      const response=await fetch("/api/integration/check",{credentials:"same-origin",cache:"no-store"});
      const data=await response.json();
      if(!response.ok)throw Error(data.message||"HTTP "+response.status);
      if(!data.connected){
        accountConfirmed=false;
        const diagnostic=Array.isArray(data.checks)?data.checks.map(check=>{
          const result=check.ok
            ?(typeof check.count==="number"?check.count+" ativo(s)":check.code==="ok"||check.code==="valid"?"confirmado":String(check.code||"confirmado"))
            :"erro "+String(check.code)+(check.subcode?" / subcódigo "+check.subcode:"");
          const reason=!check.ok&&check.reason?" — "+String(check.reason):"";
          return check.source+": "+result+reason;
        }).join(" | "):"";
        const scopes=data.permissions_status?" Permissões: "+data.permissions_status+".":"";
        detail.textContent=(data.token_valid===true?"Token validado pela Meta. ":data.token_valid===false?"Token inválido. ":data.identity_verified?"Identidade respondida pela Meta; validade não confirmada. ":"Atenção: ")+(data.message||"A conta ainda não foi confirmada.")+scopes+(diagnostic?" Consultas: "+diagnostic:"");
        if(data.token_valid===false||data.code==="token_app_mismatch"||data.code==="token_invalid_or_expired"||data.code==="token_identity_failed"){
          subscribeButton.disabled=true;
          const link=document.createElement("a");
          link.href="https://developers.facebook.com/apps/1437506684645376/";
          link.target="_blank";
          link.rel="noopener noreferrer";
          link.textContent="Abrir Meta Developers para conferir a autorização ou gerar um token válido";
          detail.append(" ",link);
        }else{
          subscribeButton.disabled=false;
        }
        return;
      }
      accountConfirmed=true;
      meta.textContent="@"+data.username+" · autorizada";
      if(!data.subscription_checked){
        detail.textContent="Conta autorizada, mas não foi possível consultar as assinaturas: "+(data.subscription_error||"erro desconhecido");
      }else if(data.messages_subscribed){
        detail.textContent="Assinatura de messages confirmada pela Meta."+(data.postbacks_subscribed?" messaging_postbacks também está ativo.":"");
      }else{
        detail.textContent="Conta autorizada, mas messages não aparece na assinatura da conta. Clique em Ativar recebimento de DMs.";
      }
    }catch(error){
      detail.textContent="Falha na verificação da API: "+error.message;
    }finally{
      checkButton.disabled=false;
    }
  }
  checkButton.addEventListener("click",verifyMeta);
  subscribeButton.addEventListener("click",async()=>{
    subscribeButton.disabled=true;
    detail.textContent="Solicitando à Meta a assinatura da conta @advisory.ofc...";
    try{
      const response=await fetch("/api/integration/subscribe",{
        method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:"{}"
      });
      const data=await response.json();
      if(!response.ok||!data.success)throw Error(data.message||"Não foi possível ativar a assinatura.");
      await verifyMeta();
    }catch(error){
      detail.textContent="A Meta não confirmou a assinatura: "+error.message;
    }finally{
      subscribeButton.disabled=false;
    }
  });

  try{
    const response=await fetch("/health",{credentials:"same-origin",cache:"no-store"});
    if(!response.ok)throw Error("health");
    const health=await response.json();
    status.textContent=health.ok&&health.database?"Serviço operacional":"Serviço requer atenção";
  }catch{
    status.textContent="Não foi possível verificar o serviço";
    return;
  }
  // O webhook grava no D1 de forma assíncrona. Atualizar apenas dados reais
  // evita que o painel pareça zerado até o usuário recarregar a página.
  let refreshing=false;
  async function refreshDashboard(){
    if(refreshing)return;
    refreshing=true;
    if(refreshButton)refreshButton.disabled=true;
    try{
      try{
        const response=await fetch("/api/integration/status",{credentials:"same-origin",cache:"no-store"});
        if(!response.ok)throw Error(response.status===401?"Sessão administrativa não autorizada":"HTTP "+response.status);
        const data=await response.json();
        if(!accountConfirmed){
          meta.textContent=data.instagram_token_configured?"Token configurado; conexão não verificada":"Token não configurado";
        }
        byId("webhook-status").textContent=data.webhook_configured?"Credenciais do webhook configuradas":"Webhook incompleto: confira META_VERIFY_TOKEN e META_APP_SECRET";
        byId("event-count").textContent=String(data.webhook_events??0);
        const last=byId("last-event");
        if(last)last.textContent=data.last_event_at||"Nenhum evento";
        notice.hidden=Boolean(data.webhook_events>0);
        notice.textContent=data.webhook_events>0?"":"Aguardando o primeiro evento de mensagem. Confira o diagnóstico em Configurações.";
      }catch(error){
        notice.hidden=false;
        notice.textContent="Não foi possível consultar a integração: "+error.message;
      }

      try{
        const response=await fetch("/api/messages/recent",{credentials:"same-origin",cache:"no-store"});
        if(!response.ok)throw Error("HTTP "+response.status);
        const data=await response.json();
        const items=Array.isArray(data.items)?data.items:[];
        byId("messages-count").textContent=String(items.length)+" recente(s)";
        byId("ad-count").textContent=String(items.filter(item=>item.from_ad).length)+" identificados";
        byId("interest-count").textContent="—";
        const list=byId("messages-list");
        list.replaceChildren();
        if(!items.length){
          const empty=document.createElement("p");
          empty.textContent="Nenhuma mensagem registrada nos eventos recentes. Não há dados simulados.";
          list.appendChild(empty);
        }else{
          for(const item of items){
            const article=document.createElement("article");
            article.className="message";
            const title=document.createElement("strong");
            title.textContent="Contato •••"+String(item.sender_id||"").slice(-6)+(item.from_ad?" · Origem de anúncio identificada":"");
            const time=document.createElement("small");
            time.textContent=item.occurred_at||"";
            const content=document.createElement("p");
            const attachments=Array.isArray(item.attachments)?item.attachments:[];
            content.textContent=item.text||("Anexos: "+attachments.join(", "));
            article.append(title,time,content);
            list.appendChild(article);
          }
        }
      }catch(error){
        byId("messages-list").textContent="Não foi possível carregar as mensagens: "+error.message;
      }
    }finally{
      refreshing=false;
      if(refreshButton)refreshButton.disabled=false;
    }
  }

  if(refreshButton)refreshButton.addEventListener("click",()=>void refreshDashboard());
  await refreshDashboard();
  void verifyMeta();
  setInterval(()=>{if(!document.hidden)void refreshDashboard();},20000);
});