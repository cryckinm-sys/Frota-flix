// Porteiro da frota: guarda e entrega os dados para todos os celulares.
// Precisa de: banco D1 ligado com o nome DB, e um segredo chamado SEGREDO.

const ENC = new TextEncoder();
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};
const json = (o, s = 200) =>
  new Response(JSON.stringify(o), { status: s, headers: { ...CORS, 'Content-Type': 'application/json' } });

const FOTOS = ['fotoIni', 'fotoFim', 'comp'];            // campos de foto (ficam guardados à parte)
const MOTORISTA_ESCREVE = ['veiculos', 'viagens', 'abast']; // o que o motorista pode gravar
const TIPOS_PROIBIDOS = ['foto', 'tent'];                // tipos internos, ninguém grava direto

// ---------- ferramentas ----------
function b64(buf) {
  const u = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
async function hmac(env, msg) {
  const k = await crypto.subtle.importKey('raw', ENC.encode(env.SEGREDO), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64(await crypto.subtle.sign('HMAC', k, ENC.encode(msg)));
}
async function hashPin(env, pin) {
  return b64(await crypto.subtle.digest('SHA-256', ENC.encode(env.SEGREDO + ':' + pin)));
}
// ---------- banco ----------
async function pegar(env, tipo, id) {
  const r = await env.DB.prepare('SELECT dados FROM itens WHERE tipo=?1 AND id=?2').bind(tipo, id).first();
  return r ? JSON.parse(r.dados) : null;
}
const stmtGravar = (env, tipo, id, obj) =>
  env.DB.prepare('INSERT INTO itens (tipo,id,dados,atualizado) VALUES (?1,?2,?3,?4) ON CONFLICT(tipo,id) DO UPDATE SET dados=excluded.dados, atualizado=excluded.atualizado')
    .bind(tipo, id, JSON.stringify(obj), Date.now());
const stmtApagar = (env, tipo, id) =>
  env.DB.prepare('DELETE FROM itens WHERE tipo=?1 AND id=?2').bind(tipo, id);

// ---------- entrada (login) ----------
async function entrar(env, request, pin) {
  const ip = request.headers.get('CF-Connecting-IP') || 'sem-ip';
  const t = (await pegar(env, 'tent', ip)) || { n: 0, ate: 0 };
  if (t.ate > Date.now()) return json({ erro: 'bloqueado', segundos: Math.ceil((t.ate - Date.now()) / 1000) }, 429);

  const cfg = await pegar(env, 'config', 'admin');
  if (!cfg) return json({ erro: 'sem_admin' }, 409);

  pin = String(pin || '').trim();
  let sessao = null;
  const h = pin ? await hashPin(env, pin) : '';
  const rv = await pegar(env, 'config', 'reserva');
  if (pin && h === cfg.hash) sessao = { tipo: 'adm', nome: '' };
  else if (pin && rv && h === rv.hash) sessao = { tipo: 'res', nome: '' };
  else if (pin) {
    const { results } = await env.DB.prepare("SELECT dados FROM itens WHERE tipo='motoristas'").all();
    for (const r of results) {
      const m = JSON.parse(r.dados);
      if (String(m.pin) === pin) { sessao = { tipo: 'mot', nome: m.nome }; break; }
    }
  }
  if (!sessao) {
    t.n++;
    if (t.n >= 5) { t.ate = Date.now() + 5 * 60 * 1000; t.n = 0; }
    await stmtGravar(env, 'tent', ip, t).run();
    return json({ erro: 'codigo_invalido' }, 401);
  }
  if (t.n || t.ate) await stmtApagar(env, 'tent', ip).run();
  return json({ ...sessao, token: await criarToken(env, sessao.tipo, sessao.nome) });
}

// ---------- rotas ----------
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    try {
      if (!env.DB || !env.SEGREDO) return json({ erro: 'Worker sem DB ou SEGREDO configurado' }, 500);
      const url = new URL(request.url);
      const rota = url.pathname;

      if (rota === '/api/estado' && request.method === 'GET') {
        return json({ temAdmin: !!(await pegar(env, 'config', 'admin')) });
      }

      if (rota === '/api/criar-admin' && request.method === 'POST') {
        if (await pegar(env, 'config', 'admin')) return json({ erro: 'admin_ja_existe' }, 403);
        const { pin } = await request.json();
        if (!/^\d{4,8}$/.test(String(pin || ''))) return json({ erro: 'pin_invalido' }, 400);
        await stmtGravar(env, 'config', 'admin', { hash: await hashPin(env, String(pin)) }).run();
        return json({ tipo: 'adm', nome: '', token: await criarToken(env, 'adm', '') });
      }

      if (rota === '/api/entrar' && request.method === 'POST') {
        const { pin } = await request.json();
        return entrar(env, request, pin);
      }

      // daqui para baixo precisa estar logado
      const quem = await lerToken(env, request);
      if (!quem) return json({ erro: 'nao_autorizado' }, 401);
      const adm = quem.t === 'adm';

      if (rota === '/api/senha-reserva' && request.method === 'POST') {
        if (!adm) return json({ erro: 'sem_permissao' }, 403);
        const { pin } = await request.json();
        if (pin === null || pin === '') {                       // apagar a senha de reserva
          await stmtApagar(env, 'config', 'reserva').run();
          return json({ ok: true, removida: true });
        }
        if (!/^\d{4,8}$/.test(String(pin))) return json({ erro: 'pin_invalido' }, 400);
        const hh = await hashPin(env, String(pin));
        const cfgA = await pegar(env, 'config', 'admin');
        if (hh === cfgA.hash) return json({ erro: 'pin_repetido' }, 409);
        const { results } = await env.DB.prepare("SELECT dados FROM itens WHERE tipo='motoristas'").all();
        if (results.some(r => String(JSON.parse(r.dados).pin) === String(pin))) return json({ erro: 'pin_repetido' }, 409);
        await stmtGravar(env, 'config', 'reserva', { hash: hh }).run();
        return json({ ok: true });
      }

      if (rota === '/api/dados' && request.method === 'GET') {
        const sql = adm
          ? "SELECT tipo,id,dados FROM itens WHERE tipo NOT IN ('foto','tent','config')"
          : quem.t === 'res'
            ? "SELECT tipo,id,dados FROM itens WHERE tipo IN ('veiculos','reservas')"
            : "SELECT tipo,id,dados FROM itens WHERE tipo NOT IN ('foto','tent','config','motoristas')";
        const { results } = await env.DB.prepare(sql).all();
        const itens = results.map(r => `{"tipo":${JSON.stringify(r.tipo)},"id":${JSON.stringify(r.id)},"dados":${r.dados}}`).join(',');
        return new Response(`{"itens":[${itens}]}`, { headers: { ...CORS, 'Content-Type': 'application/json' } });
      }

      if (rota === '/api/foto' && request.method === 'GET') {
        const f = await pegar(env, 'foto', `${url.searchParams.get('tipo')}:${url.searchParams.get('id')}:${url.searchParams.get('campo')}`);
        return json({ v: f ? f.v : null });
      }

      if (rota === '/api/salvar' && request.method === 'POST') {
        const corpo = await request.json();
        const lote = [];
        for (const it of corpo.itens || []) {
          const { tipo, id } = it;
          let d = it.dados;
          if (!tipo || id == null || !d || typeof d !== 'object') return json({ erro: 'item_invalido' }, 400);
          if (TIPOS_PROIBIDOS.includes(tipo) || tipo === 'config') return json({ erro: 'tipo_proibido' }, 403);
          const sid = String(id);
          if (quem.t === 'mot' && !MOTORISTA_ESCREVE.includes(tipo)) return json({ erro: 'sem_permissao', tipo }, 403);
          if (quem.t === 'res') {
            // quem só reserva: só cria pedido NOVO e PENDENTE. Nunca aprova nem altera.
            if (tipo !== 'reservas') return json({ erro: 'sem_permissao', tipo }, 403);
            if (await pegar(env, 'reservas', sid)) return json({ erro: 'sem_permissao' }, 403);
            const lim = (x, n) => String(x == null ? '' : x).trim().slice(0, n);
            d = { id: sid, status: 'pendente', nome: lim(d.nome, 80), setor: lim(d.setor, 80), atividade: lim(d.atividade, 300),
                  placa: lim(d.placa, 20), saida: lim(d.saida, 40), volta: lim(d.volta, 40), criado: Date.now() };
            if (!d.nome || !d.setor || !d.atividade || !d.placa) return json({ erro: 'preencha_tudo' }, 400);
          }
          if (tipo === 'motoristas') {
            const cfgA = await pegar(env, 'config', 'admin'), rvA = await pegar(env, 'config', 'reserva');
            const hh = await hashPin(env, String(d.pin || ''));
            if (hh === cfgA.hash || (rvA && hh === rvA.hash)) return json({ erro: 'pin_repetido' }, 409);
          }
          for (const k of FOTOS) {
            const fid = `${tipo}:${sid}:${k}`;
            if (typeof d[k] === 'string' && d[k]) {
              lote.push(stmtGravar(env, 'foto', fid, { v: d[k] }));
              d[k] = null; d['_' + k] = 1;
            } else if (d[k] === null && !d['_' + k]) {
              lote.push(stmtApagar(env, 'foto', fid));
            }
          }
          lote.push(stmtGravar(env, tipo, sid, d));
        }
        for (const ap of corpo.apagar || []) {
          if (!adm) return json({ erro: 'sem_permissao' }, 403);
          if (TIPOS_PROIBIDOS.includes(ap.tipo) || ap.tipo === 'config') return json({ erro: 'tipo_proibido' }, 403);
          lote.push(stmtApagar(env, ap.tipo, String(ap.id)));
          for (const k of FOTOS) lote.push(stmtApagar(env, 'foto', `${ap.tipo}:${ap.id}:${k}`));
        }
        if (lote.length) await env.DB.batch(lote);
        return json({ ok: true, gravados: lote.length });
      }

      return json({ erro: 'rota_inexistente' }, 404);
    } catch (e) {
      return json({ erro: 'falha_interna', detalhe: String(e && e.message || e) }, 500);
    }
  }
};
