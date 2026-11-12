// Nitro Brain: função da Cloudflare que liga o app do Nitro ao Gemini.
// - Só aceita pedidos de quem está logado no Firebase do Nitro E tem o e-mail liberado.
// - A chave do Gemini fica guardada na Cloudflare (Secret), nunca no GitHub.
//
// Variáveis a criar na Cloudflare (Settings > Variables and Secrets):
//   GEMINI_API_KEY  (Secret)  chave do Google AI Studio
//   ALLOWED_EMAIL   (Text)    e-mail da sua conta do Nitro
//   MODEL           (Text, opcional) padrão: gemini-3.5-flash-lite
//   FIREBASE_PROJECT_ID (Text, opcional) padrão: nitro-e3b63
//   ALLOWED_ORIGIN  (Text, opcional) padrão: https://rsantosfps-cmd.github.io

const DEFAULT_ORIGIN = 'https://rsantosfps-cmd.github.io';
const DEFAULT_PROJECT = 'nitro-e3b63';
const DEFAULT_MODEL = 'gemini-3.5-flash-lite';
const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

let jwksCache = { keys: null, exp: 0 };

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': (env && env.ALLOWED_ORIGIN) || DEFAULT_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

function json(env, body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, corsHeaders(env))
  });
}

/* ---------- login do Firebase (valida o token) ---------- */
function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64urlToText(s) { return new TextDecoder().decode(b64urlToBytes(s)); }

async function getJwks() {
  const now = Date.now();
  if (jwksCache.keys && jwksCache.exp > now) return jwksCache.keys;
  const r = await fetch(JWKS_URL);
  if (!r.ok) throw new Error('jwks');
  const j = await r.json();
  jwksCache = { keys: j.keys, exp: now + 3600 * 1000 };
  return j.keys;
}

async function verifyFirebaseToken(token, env) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('formato');
  const header = JSON.parse(b64urlToText(parts[0]));
  const payload = JSON.parse(b64urlToText(parts[1]));
  if (header.alg !== 'RS256') throw new Error('alg');
  const keys = await getJwks();
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('kid');
  const key = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
  );
  const ok = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5', key, b64urlToBytes(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1])
  );
  if (!ok) throw new Error('assinatura');
  const project = (env && env.FIREBASE_PROJECT_ID) || DEFAULT_PROJECT;
  const now = Math.floor(Date.now() / 1000);
  if (payload.aud !== project) throw new Error('aud');
  if (payload.iss !== 'https://securetoken.google.com/' + project) throw new Error('iss');
  if (!payload.exp || payload.exp < now) throw new Error('expirado');
  if (payload.iat && payload.iat > now + 300) throw new Error('iat');
  if (!payload.sub) throw new Error('sub');
  return payload;
}

/* ---------- ferramenta: Wikipédia (grátis) ---------- */
async function buscarWikipedia(consulta) {
  const q = String(consulta || '').slice(0, 200);
  if (!q) return { erro: 'consulta vazia' };
  const headers = { 'User-Agent': 'NitroAssistant/1.0 (projeto pessoal)', 'Accept': 'application/json' };
  const sUrl = 'https://pt.wikipedia.org/w/api.php?action=query&list=search&format=json&srlimit=2&srsearch=' + encodeURIComponent(q);
  const sr = await fetch(sUrl, { headers });
  if (!sr.ok) return { erro: 'busca indisponível' };
  const sj = await sr.json();
  const hits = (sj.query && sj.query.search) || [];
  if (!hits.length) return { resultado: 'nada encontrado' };
  const out = [];
  for (const h of hits) {
    const r = await fetch('https://pt.wikipedia.org/api/rest_v1/page/summary/' + encodeURIComponent(String(h.title).replace(/ /g, '_')), { headers });
    if (r.ok) {
      const j = await r.json();
      out.push({ titulo: j.title, resumo: String(j.extract || '').slice(0, 1200) });
    }
  }
  return { fonte: 'Wikipédia (pt)', resultados: out };
}

const TOOLS = [{
  functionDeclarations: [{
    name: 'buscar_wikipedia',
    description: 'Busca um resumo na Wikipédia em português. Use para conferir fatos, datas, nomes, resultados e biografias antes de responder.',
    parameters: {
      type: 'OBJECT',
      properties: { consulta: { type: 'STRING', description: 'Termo de busca curto, por exemplo "Silvio Santos".' } },
      required: ['consulta']
    }
  }]
}];

function montarSistema(contexto) {
  const hoje = new Date().toLocaleDateString('pt-BR', {
    timeZone: 'America/Sao_Paulo', weekday: 'long', day: 'numeric', month: 'long', year: 'numeric'
  });
  let s =
    'Você é o Nitro, o assistente pessoal de um streamer brasileiro. ' +
    'Fale sempre em português do Brasil, com tom leve e direto, sem enrolação. ' +
    'Responda em poucas frases, a menos que peçam mais detalhes. ' +
    'Para fatos (datas, nomes, resultados, biografias), use a ferramenta buscar_wikipedia antes de responder. ' +
    'Se não encontrar ou se o assunto for recente demais, diga que não tem certeza em vez de inventar. ' +
    'Nunca invente números, datas ou fontes. ' +
    'Hoje é ' + hoje + '.';
  if (contexto) {
    s += '\n\nContas do usuário no app (use só se a pergunta for sobre contas):\n' + contexto;
  }
  return s;
}

/* ---------- chamada ao Gemini ---------- */
function gemini(env, body) {
  const model = env.MODEL || DEFAULT_MODEL;
  const url = 'https://generativelanguage.googleapis.com/v1beta/models/' + encodeURIComponent(model) + ':generateContent';
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
    body: JSON.stringify(body)
  });
}

async function responder(env, mensagem, historico, contexto) {
  const contents = historico.map((h) => ({
    role: h.role === 'model' ? 'model' : 'user',
    parts: [{ text: String(h.text).slice(0, 2000) }]
  }));
  contents.push({ role: 'user', parts: [{ text: mensagem }] });

  let useTools = true;
  for (let i = 0; i < 4; i++) {
    const body = {
      systemInstruction: { parts: [{ text: montarSistema(contexto) }] },
      contents: contents,
      generationConfig: { temperature: 0.7, maxOutputTokens: 800 }
    };
    if (useTools) body.tools = TOOLS;

    let r = await gemini(env, body);
    if (!r.ok && r.status === 400 && useTools && i === 0) {
      // o modelo não aceitou a ferramenta: responde sem ela
      useTools = false;
      delete body.tools;
      r = await gemini(env, body);
    }
    if (!r.ok) {
      const err = new Error('gemini ' + r.status);
      err.status = r.status;
      throw err;
    }
    const j = await r.json();
    const cand = j.candidates && j.candidates[0];
    const parts = (cand && cand.content && cand.content.parts) || [];
    const calls = parts.filter((p) => p.functionCall);

    if (!calls.length) {
      const text = parts.filter((p) => p.text && !p.thought).map((p) => p.text).join('').trim();
      return text || 'Não consegui responder agora. Pergunta de novo?';
    }

    contents.push(cand.content);
    const respostas = [];
    for (const c of calls) {
      let out;
      if (c.functionCall.name === 'buscar_wikipedia') {
        try { out = await buscarWikipedia(c.functionCall.args && c.functionCall.args.consulta); }
        catch (e) { out = { erro: 'falha na busca' }; }
      } else {
        out = { erro: 'ferramenta desconhecida' };
      }
      respostas.push({ functionResponse: { name: c.functionCall.name, response: out } });
    }
    contents.push({ role: 'user', parts: respostas });
  }
  return 'Não consegui concluir a busca agora. Tenta de novo em instantes.';
}

/* ---------- entrada ---------- */
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(env) });
    if (request.method !== 'POST') return json(env, { ok: true, nome: 'Nitro Brain' });

    const authH = request.headers.get('Authorization') || '';
    const token = authH.startsWith('Bearer ') ? authH.slice(7) : '';
    let user;
    try { user = await verifyFirebaseToken(token, env); }
    catch (e) { return json(env, { erro: 'Login inválido ou expirado. Abra o Nitro e entre de novo.' }, 401); }

    const allowed = String(env.ALLOWED_EMAIL || '').trim().toLowerCase();
    if (!allowed) return json(env, { erro: 'Falta criar a variável ALLOWED_EMAIL na Cloudflare.' }, 403);
    if (String(user.email || '').toLowerCase() !== allowed) return json(env, { erro: 'Esta conta não tem permissão.' }, 403);
    if (!env.GEMINI_API_KEY) return json(env, { erro: 'Falta criar o Secret GEMINI_API_KEY na Cloudflare.' }, 500);

    let body;
    try { body = await request.json(); } catch (e) { return json(env, { erro: 'Pedido inválido.' }, 400); }
    const mensagem = String((body && body.mensagem) || '').trim().slice(0, 2000);
    if (!mensagem) return json(env, { erro: 'Mensagem vazia.' }, 400);
    const historico = Array.isArray(body.historico)
      ? body.historico.slice(-10).filter((h) => h && typeof h.text === 'string') : [];
    const contexto = typeof body.contexto === 'string' ? body.contexto.slice(0, 3000) : '';

    try {
      const resposta = await responder(env, mensagem, historico, contexto);
      return json(env, { resposta: resposta });
    } catch (e) {
      if (e && e.status === 429) return json(env, { erro: 'A cota gratuita do Gemini acabou por agora. Tenta daqui a pouco.' }, 429);
      return json(env, { erro: 'O cérebro falhou ao responder. Tenta de novo.' }, 502);
    }
  }
};
