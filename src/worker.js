const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store"}});
async function authorized(req,env){const h=req.headers.get("Authorization")||"";const token=h.startsWith("Bearer ")?h.slice(7):"";if(!token||!env.ADMIN_TOKEN)return false;const a=new TextEncoder().encode(token),b=new TextEncoder().encode(env.ADMIN_TOKEN);if(a.length!==b.length)return false;return crypto.subtle.timingSafeEqual?crypto.subtle.timingSafeEqual(a,b):await crypto.subtle.digest("SHA-256",a).then(async x=>{const y=await crypto.subtle.digest("SHA-256",b);return Array.from(new Uint8Array(x)).every((v,i)=>v===new Uint8Array(y)[i])})}
function decode64(s){const b=atob(s.replace(/-/g,"+").replace(/_/g,"/"));return Uint8Array.from(b,c=>c.charCodeAt(0))}
async function accessAuthorized(req,env){if(!env.ACCESS_TEAM_DOMAIN||!env.ACCESS_AUD||!env.ADMIN_EMAIL)return false;const token=req.headers.get("Cf-Access-Jwt-Assertion");if(!token)return false;const parts=token.split(".");if(parts.length!==3)return false;try{const header=JSON.parse(new TextDecoder().decode(decode64(parts[0])));const claims=JSON.parse(new TextDecoder().decode(decode64(parts[1])));const domain=env.ACCESS_TEAM_DOMAIN.trim().replace(/^https?:\/\//,"").replace(/\/$/,"");if(!/^[a-z0-9-]+\.cloudflareaccess\.com$/i.test(domain))return false;const issuer="https://"+domain;if(header.alg!=="RS256"||typeof header.kid!=="string"||claims.iss!==issuer||!Array.isArray(claims.aud)||!claims.aud.includes(env.ACCESS_AUD)||String(claims.email||"").toLowerCase()!==env.ADMIN_EMAIL.trim().toLowerCase()||typeof claims.exp!=="number"||claims.exp<=Date.now()/1000||typeof claims.nbf==="number"&&claims.nbf>Date.now()/1000)return false;const response=await fetch(issuer+"/cdn-cgi/access/certs");if(!response.ok)return false;const keys=await response.json();const jwk=(keys.keys||[]).find(k=>k.kid===header.kid&&k.kty==="RSA"&&(!k.alg||k.alg==="RS256"));if(!jwk)return false;const key=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);return await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,decode64(parts[2]),new TextEncoder().encode(parts[0]+"."+parts[1]))}catch{return false}}
// Interpreta somente notificações reais recebidas da Meta; não sintetiza leads.
function extractInstagramMessages(payload,receivedAt){
  if(payload?.object!=="instagram"||!Array.isArray(payload.entry))return [];
  const out=[];
  for(const entry of payload.entry){
    const events=Array.isArray(entry.messaging)?entry.messaging:[];
    for(const event of events){
      const message=event?.message;
      if(!message||typeof message!=="object"||message.is_echo===true)continue;
      if(!message.text&&!Array.isArray(message.attachments))continue;
      const sender=String(event?.sender?.id||"");
      if(!sender)continue;
      const attachments=Array.isArray(message.attachments)?message.attachments.map(a=>String(a?.type||"arquivo")).slice(0,5):[];
      const referral=event?.referral||message?.referral||null;
      const adsContext=message?.ads_context_data||event?.ads_context_data||null;
      const fromAd=Boolean(adsContext||referral&&(String(referral.source||"").toUpperCase()==="ADS"||referral.ad_id));
      let occurredAt=receivedAt;
      const timestamp=Number(event?.timestamp||entry?.time);
      if(Number.isFinite(timestamp)&&timestamp>0){
        const date=new Date(timestamp<100000000000?timestamp*1000:timestamp);
        if(!Number.isNaN(date.getTime()))occurredAt=date.toISOString();
      }
      out.push({
        id:String(message.mid||sender+":"+occurredAt+":"+String(message.text||"").slice(0,40)),
        sender_id:sender,
        text:String(message.text||"").slice(0,2000),
        attachments,
        occurred_at:occurredAt,
        from_ad:fromAd
      });
    }
  }
  return out;
}
async function getRecentInstagramMessages(db){
  // A consulta é limitada e utiliza apenas os eventos já verificados por HMAC.
  const result=await db.prepare("SELECT id,payload,received_at FROM webhook_events ORDER BY id DESC LIMIT 250").all();
  const messages=[],seen=new Set();
  for(const row of result.results||[]){
    let payload;
    try{payload=JSON.parse(row.payload)}catch{continue}
    for(const msg of extractInstagramMessages(payload,row.received_at)){
      if(seen.has(msg.id))continue;
      seen.add(msg.id);
      messages.push(msg);
    }
  }
  messages.sort((a,b)=>String(b.occurred_at).localeCompare(String(a.occurred_at)));
  return messages.slice(0,50);
}

// Diagnóstico privado: Login Unificado usa graph.facebook.com e SUAT.
const META_GRAPH_VERSION="v26.0";
async function graphRequest(env,path,method="GET",fields){
  if(!env.META_ACCESS_TOKEN)return {ok:false,code:"token_missing",message:"META_ACCESS_TOKEN não está disponível no Worker."};
  try{
    const response=await fetch("https://graph.facebook.com/"+META_GRAPH_VERSION+path,{
      method,
      headers:{"Authorization":"Bearer "+env.META_ACCESS_TOKEN,...(fields?{"Content-Type":"application/x-www-form-urlencoded"}:{})},
      ...(fields?{body:new URLSearchParams(fields).toString()}:{})
    });
    const data=await response.json();
    if(!response.ok||data?.error){
      return {ok:false,code:String(data?.error?.code??"meta_http_"+response.status),
        message:String(data?.error?.message||"Falha na API da Meta.").slice(0,240)};
    }
    return {ok:true,data};
  }catch{
    return {ok:false,code:"meta_unreachable",message:"Não foi possível consultar a API da Meta neste momento."};
  }
}
async function findAssignedInstagram(env){
  const result=await graphRequest(env,"/me/assigned_instagram_accounts?fields=id,username&limit=100");
  if(!result.ok)return result;
  const accounts=Array.isArray(result.data?.data)?result.data.data:[];
  if(!accounts.length){
    // Consulta aceita pela Meta com lista vazia: isso é diferente de token inválido.
    const identity=await graphRequest(env,"/me?fields=id,client_business_id");
    return {ok:false,code:"no_instagram_assets_assigned",
      message:"A Meta respondeu à consulta, mas retornou zero contas Instagram atribuídas a este token. Verifique o acesso aos ativos do usuário de sistema no portfólio Sales Hub.",
      token_identity_verified:identity.ok,client_business_detected:!!identity.data?.client_business_id,
      assigned_instagram_count:0};
  }
  const account=accounts.find(a=>String(a?.username||"").replace(/^@/,"").toLowerCase()==="advisory.ofc");
  if(!account?.id)return {ok:false,code:"target_instagram_not_shared",
    message:"A Meta retornou "+accounts.length+" conta(s) Instagram para o token, mas não @advisory.ofc. Confira qual conta foi compartilhada na autorização.",
    assigned_instagram_count:accounts.length};
  return {ok:true,account_id:String(account.id),username:String(account.username)};
}
function subscribedFields(data){
  const applications=Array.isArray(data?.data)?data.data:[];
  return [...new Set(applications.flatMap(app=>Array.isArray(app?.subscribed_fields)?app.subscribed_fields:[]))];
}
async function checkMetaIntegration(env){
  const account=await findAssignedInstagram(env);
  if(!account.ok)return {connected:false,...account};
  const subscription=await graphRequest(env,"/"+encodeURIComponent(account.account_id)+"/subscribed_apps");
  if(!subscription.ok)return {connected:true,username:account.username,account_id:account.account_id,
    subscription_checked:false,subscription_error:subscription.message,subscription_error_code:subscription.code};
  const fields=subscribedFields(subscription.data);
  return {connected:true,username:account.username,account_id:account.account_id,
    subscription_checked:true,subscribed_fields:fields,
    messages_subscribed:fields.includes("messages"),
    postbacks_subscribed:fields.includes("messaging_postbacks")};
}
export default {async fetch(req,env){const url=new URL(req.url);if(url.pathname==="/health")return json({ok:true,service:"instagram-sales-hub",database:!!env.DB});
if(url.pathname==="/webhooks/instagram"&&req.method==="GET"){if(!env.META_VERIFY_TOKEN)return json({error:"not_configured"},503);const p=url.searchParams;return p.get("hub.mode")==="subscribe"&&p.get("hub.verify_token")===env.META_VERIFY_TOKEN?new Response(p.get("hub.challenge")||""):json({error:"invalid_challenge"},403)}
if(url.pathname==="/webhooks/instagram"&&req.method==="POST"){if(!env.META_APP_SECRET||!env.DB)return json({error:"not_configured"},503);const signature=req.headers.get("x-hub-signature-256")||"";if(!/^sha256=[a-f0-9]{64}$/i.test(signature))return json({error:"invalid_signature"},401);const raw=await req.arrayBuffer(),key=await crypto.subtle.importKey("raw",new TextEncoder().encode(env.META_APP_SECRET),{name:"HMAC",hash:"SHA-256"},false,["sign"]);const signed=Array.from(new Uint8Array(await crypto.subtle.sign("HMAC",key,raw)),v=>v.toString(16).padStart(2,"0")).join("");const expected="sha256="+signed;if(expected.length!==signature.length||![...expected].every((c,i)=>c===signature[i]))return json({error:"invalid_signature"},401);let body;try{body=JSON.parse(new TextDecoder().decode(raw))}catch{return json({error:"invalid_json"},400)};await env.DB.prepare("INSERT INTO webhook_events (payload,received_at) VALUES (?,datetime('now'))").bind(JSON.stringify(body)).run();return json({received:true})}
if(req.method==="GET" && (url.pathname==="/" || url.pathname==="/index.html" || url.pathname==="/style.css" || url.pathname==="/app.js")){if(!env.ASSETS)return json({error:"assets_not_bound"},503);return env.ASSETS.fetch(req)}
if(!await accessAuthorized(req,env) && !await authorized(req,env))return json({error:"unauthorized"},401);if(!env.DB)return json({error:"database_not_bound"},503);
if(url.pathname==="/api/integration/status"&&req.method==="GET"){const configured=!!(env.META_APP_SECRET&&env.META_VERIFY_TOKEN);const count=await env.DB.prepare("SELECT COUNT(*) AS total, MAX(received_at) AS latest FROM webhook_events").first();return json({webhook_configured:configured,webhook_events:Number(count?.total||0),last_event_at:count?.latest||null,instagram_token_configured:!!env.META_ACCESS_TOKEN,instagram_connected:false,messages_available:false,ad_contacts_available:false})}
if(url.pathname==="/api/integration/check"&&req.method==="GET"){
  return json(await checkMetaIntegration(env));
}
if(url.pathname==="/api/integration/subscribe"&&req.method==="POST"){
  const origin=req.headers.get("Origin");
  if(origin&&origin!==url.origin)return json({error:"invalid_origin"},403);
  const account=await findAssignedInstagram(env);
  if(!account.ok)return json({success:false,code:account.code,message:account.message},422);
  const response=await graphRequest(env,"/"+encodeURIComponent(account.account_id)+"/subscribed_apps","POST",
    {subscribed_fields:"messages,messaging_postbacks"});
  if(!response.ok)return json({success:false,code:response.code,message:response.message},422);
  if(response.data?.success!==true)return json({success:false,message:"A Meta não confirmou a assinatura.",details:"Confira os logs da API da Meta."},422);
  return json({success:true,username:account.username,message:"Conta inscrita em messages e messaging_postbacks."});
}
if(url.pathname==="/api/messages/recent"&&req.method==="GET"){return json({items:await getRecentInstagramMessages(env.DB)});}
return json({error:"not_found"},404)
}};
