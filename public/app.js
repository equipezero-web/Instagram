document.addEventListener("DOMContentLoaded",async()=>{
  const byId=id=>document.getElementById(id);
  const status=byId("status"),notice=byId("notice"),meta=byId("meta-status");
  try{
    const response=await fetch("/health",{credentials:"same-origin",cache:"no-store"});
    if(!response.ok)throw Error("health");
    const health=await response.json();
    status.textContent=health.ok&&health.database?"Worker e D1 detectados":"Serviço requer atenção";
  }catch{
    status.textContent="Não foi possível verificar o serviço";
    return;
  }
  try{
    const response=await fetch("/api/integration/status",{credentials:"same-origin",cache:"no-store"});
    if(!response.ok)throw Error(response.status===401?"Sessão administrativa não autorizada":"HTTP "+response.status);
    const data=await response.json();
    meta.textContent=data.instagram_token_configured?"Token configurado; conexão não verificada":"Token não configurado";
    byId("webhook-status").textContent=data.webhook_configured?"Credenciais do webhook configuradas":"Webhook incompleto: confira META_VERIFY_TOKEN e META_APP_SECRET";
    byId("event-count").textContent=String(data.webhook_events??0);
    const last=byId("last-event");
    if(last)last.textContent=data.last_event_at||"Nenhum evento";
    notice.textContent=data.webhook_events>0
      ?"O Worker recebeu notificações da Meta. As mensagens abaixo são extraídas somente de eventos reais; a conexão com a API ainda não foi validada por consulta."
      :"Nenhum evento de webhook foi registrado no D1. Faça um teste com outra conta Instagram autorizada e confira as assinaturas na Meta.";
  }catch(error){
    notice.textContent="Não foi possível consultar a integração: "+error.message;
    return;
  }
  try{
    const response=await fetch("/api/messages/recent",{credentials:"same-origin",cache:"no-store"});
    if(!response.ok)throw Error("HTTP "+response.status);
    const data=await response.json();
    const items=Array.isArray(data.items)?data.items:[];
    byId("messages-count").textContent=String(items.length)+" recente(s)";
    byId("ad-count").textContent=String(items.filter(item=>item.from_ad).length)+" identificados";
    const list=byId("messages-list");
    list.replaceChildren();
    if(!items.length){
      const empty=document.createElement("p");
      empty.textContent="Nenhuma mensagem registrada nos eventos recentes. Não há dados simulados.";
      list.appendChild(empty);
      return;
    }
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
  }catch(error){
    const list=byId("messages-list");
    list.textContent="Não foi possível carregar as mensagens: "+error.message;
  }
});