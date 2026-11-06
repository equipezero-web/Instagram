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
function metaSafeErrorDetails(error,env){
  // Apenas diagnóstico para o painel protegido por Cloudflare Access.
  // Nunca retornar tokens, segredo, URLs ou identificadores de rastreamento.
  const raw=String(error?.message||error?.error_user_msg||"");
  let safe=raw;
  for(const secret of [env.META_ACCESS_TOKEN,env.META_APP_SECRET,env.META_VERIFY_TOKEN]){
    if(typeof secret==="string"&&secret.length>=8)safe=safe.split(secret).join("[oculto]");
  }
  safe=safe
    .replace(/(?:access_token|input_token|client_secret|appsecret_proof|app_secret)\s*[=:]\s*[^\s&;,]+/gi,"[credencial oculta]")
    .replace(/\bBearer\s+\S+/gi,"Bearer [oculto]")
    .replace(/\b(?:EAA|IGA|IGQV|IGAA)[A-Za-z0-9_\-]{15,}\b/g,"[token oculto]")
    .replace(/https?:\/\/\S+/gi,"[URL oculta]")
    .replace(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g,"[email oculto]")
    .replace(/[\r\n\t]+/g," ").trim();
  return {type:String(error?.type||"").slice(0,45),reason:safe.slice(0,220)};
}

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
      const safe=metaSafeErrorDetails(data?.error,env);
      return {ok:false,code:String(data?.error?.code??"meta_http_"+response.status),
        message:safe.reason||"Falha na API da Meta.",error_type:safe.type,
        subcode:data?.error?.error_subcode??null};
    }
    return {ok:true,data};
  }catch{
    return {ok:false,code:"meta_unreachable",message:"Não foi possível consultar a API da Meta neste momento."};
  }
}
async function debugMetaToken(env){
  const appId=String(env.META_APP_ID||"1437506684645376");
  if(!env.META_ACCESS_TOKEN||!env.META_APP_SECRET){
    return {ok:false,code:"debug_secrets_missing"};
  }
  try{
    const url=new URL("https://graph.facebook.com/"+META_GRAPH_VERSION+"/debug_token");
    url.searchParams.set("input_token",env.META_ACCESS_TOKEN);
    const response=await fetch(url.toString(),{
      headers:{"Authorization":"Bearer "+appId+"|"+env.META_APP_SECRET}
    });
    const result=await response.json();
    if(!response.ok||result.error){
      const safe=metaSafeErrorDetails(result.error,env);
      return {ok:false,code:String(result.error?.code??response.status),
        message:safe.reason,error_type:safe.type,
        subcode:result.error?.error_subcode??null};
    }
    const data=result.data||{};
    return {ok:true,is_valid:data.is_valid===true,
      app_id:String(data.app_id||""),type:String(data.type||"desconhecido"),
      expires_at:Number(data.expires_at||0),
      scopes:Array.isArray(data.scopes)?data.scopes.map(String):[]};
  }catch{
    return {ok:false,code:"debug_unavailable"};
  }
}
async function findAssignedInstagram(env){
  const debug=await debugMetaToken(env);
  const checks=[{source:"debug_token",ok:debug.ok,
    code:debug.ok?(debug.is_valid?"valid":"invalid"):debug.code,
    ...(!debug.ok&&debug.message?{reason:debug.message}:{}),
    ...(!debug.ok&&debug.error_type?{error_type:debug.error_type}:{}),
    ...(debug.subcode?{subcode:debug.subcode}:{})}];
  if(debug.ok&&!debug.is_valid){
    return {ok:false,code:"token_invalid",token_valid:false,identity_verified:false,
      message:"A verificação oficial da Meta confirmou que META_ACCESS_TOKEN está inválido ou não está mais ativo. Substitua-o por um token válido emitido para o Sales Hub.",checks};
  }
  const expectedAppId=String(env.META_APP_ID||"1437506684645376");
  if(debug.ok&&debug.app_id!==expectedAppId){
    return {ok:false,code:"token_app_mismatch",token_valid:true,identity_verified:false,
      message:"O token é válido, mas foi emitido para outro aplicativo da Meta, não para Sales Hub.",checks};
  }
  const identity=await graphRequest(env,"/me?fields=id");
  checks.push({source:"token_identity",ok:identity.ok,code:identity.ok?"ok":identity.code,
    ...(!identity.ok&&identity.message?{reason:identity.message}:{}),
    ...(!identity.ok&&identity.error_type?{error_type:identity.error_type}:{}),
    ...(identity.subcode?{subcode:identity.subcode}:{})});
  // A consulta /me pode não estar autorizada para alguns tokens de sistema/Instagram.
  // Não encerrar o diagnóstico por erro de permissão: o acesso direto ao IG ID é
  // uma verificação independente e utiliza somente a permissão de Instagram.
  if(!identity.ok&&identity.code==="190"){
    return {ok:false,code:"token_invalid_or_expired",
      token_valid:debug.ok?debug.is_valid:null,identity_verified:false,
      message:"A Meta devolveu erro 190 ao consultar /me. Confira a validade do token pelo depurador da Meta.",checks};
  }
  if(identity.ok){
    // client_business_id é opcional e não prova de validade do token.
    const clientBusiness=await graphRequest(env,"/me?fields=client_business_id");
    checks.push({source:"client_business_id",ok:clientBusiness.ok,
      code:clientBusiness.ok?(clientBusiness.data?.client_business_id?"found":"not_returned"):clientBusiness.code,
      ...(clientBusiness.subcode?{subcode:clientBusiness.subcode}:{})});
  }else{
    checks.push({source:"client_business_id",ok:false,code:"not_attempted_identity_unavailable"});
  }
  const scopes=debug.ok?debug.scopes:null;
  // ID identificado na tela API setup with Unified Login (Meta Developers).
  // É diferente do ID de ativo apresentado no Business Suite.
  const igId=String(env.META_INSTAGRAM_USER_ID||"17841449038623629");
  const direct=await graphRequest(env,"/"+encodeURIComponent(igId)+"?fields=id,username");
  const expectedUsername="advisory.ofc";
  const directMatched=direct.ok&&
    String(direct.data?.username||"").replace(/^@/,"").toLowerCase()===expectedUsername;
  checks.push({source:"meta_setup_ig_user_id",ok:direct.ok,
    code:direct.ok?(directMatched?"matched":"different_username"):direct.code,
    ...(!direct.ok&&direct.message?{reason:direct.message}:{}),
    ...(!direct.ok&&direct.error_type?{error_type:direct.error_type}:{}),
    ...(direct.subcode?{subcode:direct.subcode}:{})});
  if(directMatched){
    return {ok:true,account_id:String(direct.data.id||igId),username:expectedUsername,
      identity_verified:true,token_valid:debug.ok?debug.is_valid:null,
      token_type:debug.ok?debug.type:null,discovery_source:"meta_setup_ig_user_id",
      permissions:scopes,checks};
  }
  const required=["instagram_basic","instagram_manage_messages"];
  const missing=scopes===null?[]:required.filter(x=>!scopes.includes(x));
  const businessId=String(env.META_BUSINESS_ID||"2184116235477697");
  const candidateId=String(env.META_INSTAGRAM_ASSET_ID||"972986455905159");
  const methods=[{name:"unified_login_assets",
    path:"/me/assigned_instagram_accounts?fields=id,username&limit=100"}];
  if(scopes?.includes("business_management")){
    methods.push(
      {name:"business_owned_instagram_accounts",
        path:"/"+encodeURIComponent(businessId)+"/owned_instagram_accounts?fields=id,username&limit=100"},
      {name:"business_instagram_accounts",
        path:"/"+encodeURIComponent(businessId)+"/instagram_business_accounts?fields=id,username&limit=100"}
    );
  }else{
    checks.push({source:"business_edges",ok:false,
      code:scopes===null?"not_attempted_scopes_unknown":"business_management_not_granted"});
  }
  const candidateIds=new Set();
  for(const method of methods){
    const result=await graphRequest(env,method.path);
    if(!result.ok){
      checks.push({source:method.name,ok:false,code:result.code,
        ...(result.subcode?{subcode:result.subcode}:{})});
      continue;
    }
    const accounts=Array.isArray(result.data?.data)?result.data.data:[];
    checks.push({source:method.name,ok:true,count:accounts.length});
    for(const account of accounts){
      if(account?.id)candidateIds.add(String(account.id));
      if(String(account?.username||"").replace(/^@/,"").toLowerCase()==="advisory.ofc"&&account?.id){
        return {ok:true,account_id:String(account.id),username:"advisory.ofc",
          identity_verified:true,token_valid:debug.ok?debug.is_valid:null,
          token_type:debug.ok?debug.type:null,discovery_source:method.name,
          permissions:scopes,checks};
      }
    }
  }
  // Identificador de ativo do Business Suite pode não ser o IG User ID do Graph.
  if(/^\d{7,22}$/.test(candidateId))candidateIds.add(candidateId);
  for(const id of [...candidateIds].slice(0,20)){
    const result=await graphRequest(env,"/"+encodeURIComponent(id)+"?fields=id,username");
    const fromBusinessAsset=id===candidateId;
    checks.push({
      source:fromBusinessAsset?"business_asset_direct_lookup":"instagram_id_direct_lookup",
      ok:result.ok,
      code:result.ok
        ?(String(result.data?.username||"").replace(/^@/,"").toLowerCase()==="advisory.ofc"?"matched":"different_account_or_not_instagram")
        :result.code,
      ...(result.subcode?{subcode:result.subcode}:{}),
    });
    if(!result.ok)continue;
    if(String(result.data?.username||"").replace(/^@/,"").toLowerCase()==="advisory.ofc"){
      return {ok:true,account_id:String(result.data.id||id),username:"advisory.ofc",
        identity_verified:true,token_valid:debug.ok?debug.is_valid:null,
        token_type:debug.ok?debug.type:null,
        discovery_source:"direct_profile",permissions:scopes,checks};
    }
  }
  const accessDenied=[debug,identity,direct].some(c=>!c.ok&&c.code==="200");
  return {ok:false,code:missing.length?"instagram_scopes_missing":
      accessDenied?"meta_permission_denied":"account_discovery_inconclusive",
    token_valid:debug.ok?debug.is_valid:null,identity_verified:identity.ok,
    token_type:debug.ok?debug.type:null,permissions:scopes,
    permissions_status:scopes===null?"inspeção indisponível":scopes.join(", ")||"nenhum scope retornado",
    missing_permissions:missing,
    message:missing.length?
      "A Meta informou que faltam permissões no token: "+missing.join(", ")+".":
      accessDenied?
        "A Meta retornou erro de permissão (código 200) em uma ou mais consultas. Isso não prova que o token expirou. A consulta direta da conta também foi tentada; veja os códigos abaixo. O recebimento de webhooks deve ser investigado separadamente.":
        "Não foi possível confirmar @advisory.ofc na API. A consulta direta ao IG User ID foi tentada; veja o resultado de meta_setup_ig_user_id abaixo.",
    checks};
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
export default {async fetch(req,env){const url=new URL(req.url);if(url.pathname==="/health")return json({ok:true,service:"instagram-sales-hub",database:!!env.DB,release:"meta200-fallback-webhook-20261106"});
if(url.pathname==="/webhooks/instagram"&&req.method==="GET"){if(!env.META_VERIFY_TOKEN)return json({error:"not_configured"},503);const p=url.searchParams;return p.get("hub.mode")==="subscribe"&&p.get("hub.verify_token")===env.META_VERIFY_TOKEN?new Response(p.get("hub.challenge")||""):json({error:"invalid_challenge"},403)}
if(url.pathname==="/webhooks/instagram"&&req.method==="POST"){
  // Registros técnicos sem IP, token, assinatura ou conteúdo de mensagens.
  const log=(stage,status)=>console.info("sales_hub_webhook",JSON.stringify({stage,status}));
  if(!env.META_APP_SECRET||!env.DB){
    log("runtime_secret_or_database_missing",503);
    return json({error:"not_configured"},503);
  }
  const signature=req.headers.get("x-hub-signature-256")||"";
  if(!/^sha256=[a-f0-9]{64}$/i.test(signature)){
    log("invalid_signature_header",401);
    return json({error:"invalid_signature"},401);
  }
  let raw;
  try{raw=await req.arrayBuffer()}catch{
    log("body_read_error",400);
    return json({error:"invalid_body"},400);
  }
  let signed;
  try{
    const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(env.META_APP_SECRET),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
    signed=Array.from(new Uint8Array(await crypto.subtle.sign("HMAC",key,raw)),v=>v.toString(16).padStart(2,"0")).join("");
  }catch{
    log("signature_computation_error",500);
    return json({error:"signature_verification_failed"},500);
  }
  const expected="sha256="+signed;
  const actual=signature.toLowerCase();
  if(expected.length!==actual.length||![...expected].every((c,i)=>c===actual[i])){
    log("signature_mismatch",401);
    return json({error:"invalid_signature"},401);
  }
  let body;
  try{body=JSON.parse(new TextDecoder().decode(raw))}catch{
    log("invalid_json",400);
    return json({error:"invalid_json"},400);
  }
  try{
    await env.DB.prepare("INSERT INTO webhook_events (payload,received_at) VALUES (?,datetime('now'))")
      .bind(JSON.stringify(body)).run();
  }catch{
    log("database_insert_failed",500);
    return json({error:"database_insert_failed"},500);
  }
  log("event_saved",200);
  return json({received:true});
}

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
