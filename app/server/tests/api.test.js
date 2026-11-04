'use strict';

/**
 * Testes de integração da API — Secure by Design.
 * Usa node:test e fetch nativo (Node 22).
 *
 * Cada suite cria sua própria instância isolada da aplicação com banco temporário.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { randomUUID } = require('crypto');
const http = require('http');
const argon2 = require('argon2');

const { criarApp } = require('../server');
const { criarBancoDeDados } = require('../src/db/database');
const { carregarConfig } = require('../src/config/env');
const { obterDummyHash } = require('../src/routes/login');

// Parâmetros Argon2id para criação de usuários nos testes
const ARGON2_OPCOES = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

// SESSION_SECRET válido para testes
const SESSION_SECRET_TESTE = 'segredo-de-teste-com-pelo-menos-32-caracteres-ok';

/**
 * Cria uma instância isolada do app para testes.
 *
 * @param {object} [opcoes]
 * @param {function(): number} [opcoes.getNow]
 * @param {object} [opcoes.configOverrides]
 * @returns {Promise<{app, server, baseUrl, db, dbPath, cleanup}>}
 */
async function criarAppDeTeste(opcoes = {}) {
  const dbPath = path.join(os.tmpdir(), `teste-${randomUUID()}.db`);
  const db = criarBancoDeDados(dbPath);

  const configOverrides = {
    sessionSecret: SESSION_SECRET_TESTE,
    port: 0, // porta efêmera
    nodeEnv: 'test',
    databasePath: dbPath,
    ...opcoes.configOverrides,
  };

  const app = criarApp({
    getNow: opcoes.getNow ?? Date.now,
    dbInstance: db,
    configOverrides,
  });

  const servidor = http.createServer(app);

  await new Promise((resolve) => servidor.listen(0, '127.0.0.1', resolve));

  const porta = servidor.address().port;
  const baseUrl = `http://127.0.0.1:${porta}`;

  const cleanup = async () => {
    try { app.sessionStore?.stopInterval?.(); } catch { /* ignora */ }
    try { servidor.closeAllConnections?.(); } catch { /* ignora */ }
    await new Promise((resolve) => servidor.close(resolve));
    try { db.close(); } catch { /* ignora */ }
    try { fs.unlinkSync(dbPath); } catch { /* ignora */ }
  };

  return { app, server: servidor, baseUrl, db, dbPath, cleanup };
}

/**
 * Cria um usuário de teste diretamente no banco.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {string} username
 * @param {string} password
 */
async function criarUsuarioDeTeste(db, username, password) {
  const hash = await argon2.hash(password, ARGON2_OPCOES);
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
}

/**
 * Obtém o token CSRF e o cookie de sessão de um endpoint.
 *
 * @param {string} baseUrl
 * @returns {Promise<{csrfToken: string, cookie: string}>}
 */
async function obterCsrfECookie(baseUrl) {
  const res = await fetch(`${baseUrl}/api/csrf`);
  const { csrfToken } = await res.json();
  const cookie = res.headers.get('set-cookie') ?? '';
  return { csrfToken, cookie };
}

/**
 * Faz login e retorna os cookies e o token CSRF pós-login.
 */
async function fazerLogin(baseUrl, username, password) {
  const { csrfToken, cookie } = await obterCsrfECookie(baseUrl);

  const res = await fetch(`${baseUrl}/api/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken,
      'Cookie': cookie,
    },
    body: JSON.stringify({ username, password }),
  });

  const cookiePos = res.headers.get('set-cookie') ?? cookie;
  const corpo = await res.json();

  // Obtém novo token CSRF pós-login
  const resNovoToken = await fetch(`${baseUrl}/api/csrf`, {
    headers: { 'Cookie': cookiePos },
  });
  const novoCsrf = resNovoToken.headers.get('set-cookie') ?? cookiePos;
  const { csrfToken: csrfPosLogin } = await resNovoToken.json();

  return { res, cookie: novoCsrf, csrfToken: csrfPosLogin, corpo };
}

// ============================================================
// TESTES
// ============================================================

describe('Proteção de rotas autenticadas', () => {
  let ctx;

  before(async () => { ctx = await criarAppDeTeste(); });
  after(async () => { await ctx.cleanup(); });

  test('GET /api/me sem sessão retorna 401', async () => {
    const res = await fetch(`${ctx.baseUrl}/api/me`);
    assert.equal(res.status, 401);
    const corpo = await res.json();
    assert.ok(corpo.erro);
  });

  test('GET /api/dashboard sem sessão retorna 401', async () => {
    const res = await fetch(`${ctx.baseUrl}/api/dashboard`);
    assert.equal(res.status, 401);
    const corpo = await res.json();
    assert.ok(corpo.erro);
  });
});

describe('Login inválido', () => {
  let ctx;

  before(async () => {
    ctx = await criarAppDeTeste();
    await criarUsuarioDeTeste(ctx.db, 'testusuario', 'SenhaCorreta123!');
  });
  after(async () => { await ctx.cleanup(); });

  test('Login com senha errada retorna 401 com mensagem genérica', async () => {
    const { csrfToken, cookie } = await obterCsrfECookie(ctx.baseUrl);

    const res = await fetch(`${ctx.baseUrl}/api/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Cookie': cookie,
      },
      body: JSON.stringify({ username: 'testusuario', password: 'SenhaErrada999!' }),
    });

    assert.equal(res.status, 401);
    const corpo = await res.json();
    assert.equal(corpo.erro, 'Usuário ou senha inválidos');
  });

  test('POST sem token CSRF retorna 403', async () => {
    const res = await fetch(`${ctx.baseUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'testusuario', password: 'SenhaCorreta123!' }),
    });
    assert.equal(res.status, 403);
  });
});

describe('Rate limiting de login', () => {
  let ctx;

  before(async () => {
    ctx = await criarAppDeTeste();
    await criarUsuarioDeTeste(ctx.db, 'usuarioteste', 'SenhaCorreta123!');
  });
  after(async () => { await ctx.cleanup(); });

  test('5 falhas consecutivas e a 6ª retorna 429', async () => {
    const { csrfToken, cookie } = await obterCsrfECookie(ctx.baseUrl);

    // 5 falhas
    for (let i = 0; i < 5; i++) {
      await fetch(`${ctx.baseUrl}/api/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
          'Cookie': cookie,
        },
        body: JSON.stringify({ username: 'usuarioteste', password: 'SenhaErrada!' }),
      });
    }

    // 6ª tentativa deve ser bloqueada
    const res = await fetch(`${ctx.baseUrl}/api/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Cookie': cookie,
      },
      body: JSON.stringify({ username: 'usuarioteste', password: 'SenhaErrada!' }),
    });

    assert.equal(res.status, 429);
  });
});

describe('Login bem-sucedido e cookie', () => {
  let ctx;

  before(async () => {
    ctx = await criarAppDeTeste();
    await criarUsuarioDeTeste(ctx.db, 'usuariook', 'SenhaCorreta123!');
  });
  after(async () => { await ctx.cleanup(); });

  test('Login bem-sucedido retorna 200 e cookie sid com HttpOnly e SameSite=Lax', async () => {
    const { csrfToken, cookie } = await obterCsrfECookie(ctx.baseUrl);

    const res = await fetch(`${ctx.baseUrl}/api/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Cookie': cookie,
      },
      body: JSON.stringify({ username: 'usuariook', password: 'SenhaCorreta123!' }),
    });

    assert.equal(res.status, 200);
    const corpo = await res.json();
    assert.equal(corpo.username, 'usuariook');

    const setCookie = res.headers.get('set-cookie') ?? '';
    assert.ok(setCookie.toLowerCase().includes('httponly'), 'Cookie deve ter HttpOnly');
    assert.ok(setCookie.toLowerCase().includes('samesite=lax'), 'Cookie deve ter SameSite=Lax');
    assert.ok(setCookie.includes('sid'), 'Cookie deve chamar-se sid');
  });
});

describe('Cookie Secure em produção', () => {
  let ctx;

  before(async () => {
    ctx = await criarAppDeTeste({ configOverrides: { nodeEnv: 'production' } });
    await criarUsuarioDeTeste(ctx.db, 'usuarioprod', 'SenhaCorreta123!');
  });
  after(async () => { await ctx.cleanup(); });

  test('Cookie tem flag Secure em NODE_ENV=production', async () => {
    // Com trust proxy habilitado (app.set('trust proxy', 1)), a terminação TLS do Nginx
    // é informada via cabeçalho x-forwarded-proto: https.
    // O Express-Session então emite o cookie sid com a flag Secure obrigatória.
    const res = await fetch(`${ctx.baseUrl}/api/csrf`, {
      headers: { 'x-forwarded-proto': 'https' },
    });
    assert.equal(res.status, 200);

    const setCookie = res.headers.get('set-cookie') ?? '';
    assert.ok(setCookie.includes('sid'), 'Cookie sid deve ser emitido');
    assert.ok(
      /;\s*Secure/i.test(setCookie),
      `Cookie sid emitido em produção deve possuir a flag Secure. Cabeçalho recebido: ${setCookie}`
    );
  });
});

describe('Logout', () => {
  let ctx;

  before(async () => {
    ctx = await criarAppDeTeste();
    await criarUsuarioDeTeste(ctx.db, 'usuariologout', 'SenhaCorreta123!');
  });
  after(async () => { await ctx.cleanup(); });

  test('Após logout, /api/dashboard retorna 401', async () => {
    // Faz login
    const { cookie, csrfToken } = await fazerLogin(ctx.baseUrl, 'usuariologout', 'SenhaCorreta123!');

    // Confirma que está autenticado
    const resDash = await fetch(`${ctx.baseUrl}/api/dashboard`, {
      headers: { 'Cookie': cookie },
    });
    assert.equal(resDash.status, 200, 'Deve estar autenticado antes do logout');

    // Faz logout
    const resLogout = await fetch(`${ctx.baseUrl}/api/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Cookie': cookie,
      },
      body: JSON.stringify({}),
    });
    assert.equal(resLogout.status, 204);

    // Tenta acessar dashboard com cookie antigo
    const resDash2 = await fetch(`${ctx.baseUrl}/api/dashboard`, {
      headers: { 'Cookie': cookie },
    });
    assert.equal(resDash2.status, 401, 'Após logout, deve retornar 401');
  });

  test('Cookie antigo não funciona após logout', async () => {
    const { cookie: cookieAntigo, csrfToken } = await fazerLogin(ctx.baseUrl, 'usuariologout', 'SenhaCorreta123!');

    // Logout com o cookie antigo
    await fetch(`${ctx.baseUrl}/api/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Cookie': cookieAntigo,
      },
      body: JSON.stringify({}),
    });

    // Tenta usar o cookie antigo
    const res = await fetch(`${ctx.baseUrl}/api/me`, {
      headers: { 'Cookie': cookieAntigo },
    });
    assert.equal(res.status, 401);
  });
});

describe('Content-Type', () => {
  let ctx;

  before(async () => { ctx = await criarAppDeTeste(); });
  after(async () => { await ctx.cleanup(); });

  test('POST com Content-Type errado retorna 415', async () => {
    const res = await fetch(`${ctx.baseUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: 'username=a&password=b',
    });
    assert.equal(res.status, 415);
  });
});

describe('Validação de SESSION_SECRET', () => {
  test('carregarConfig lança erro sem SESSION_SECRET', () => {
    // Remove temporariamente o SESSION_SECRET do ambiente
    const secretAntigo = process.env.SESSION_SECRET;
    delete process.env.SESSION_SECRET;

    try {
      assert.throws(
        () => carregarConfig({}),
        /SESSION_SECRET/
      );
    } finally {
      if (secretAntigo !== undefined) process.env.SESSION_SECRET = secretAntigo;
    }
  });

  test('carregarConfig lança erro com SESSION_SECRET < 32 chars', () => {
    assert.throws(
      () => carregarConfig({ sessionSecret: 'curto' }),
      /SESSION_SECRET/
    );
  });
});

describe('Expiração de sessão anônima (injeção de tempo)', () => {
  let ctx;
  // Simula tempo: começa agora, avança 16 min na segunda chamada
  let tempoSimulado = Date.now();
  const getNow = () => tempoSimulado;

  before(async () => {
    ctx = await criarAppDeTeste({ getNow });
  });
  after(async () => { await ctx.cleanup(); });

  test('Sessão anônima expirada resulta em nova sessão', async () => {
    // Obtém sessão anônima
    const res1 = await fetch(`${ctx.baseUrl}/api/csrf`);
    const cookie1 = res1.headers.get('set-cookie') ?? '';
    const { csrfToken: token1 } = await res1.json();

    // Avança o tempo 16 minutos (além do limite de 15 min para sessões anônimas)
    tempoSimulado += 16 * 60 * 1000;

    // Requisição com o cookie antigo — deve detectar expiração e criar nova sessão
    const res2 = await fetch(`${ctx.baseUrl}/api/csrf`, {
      headers: { 'Cookie': cookie1 },
    });
    assert.equal(res2.status, 200, 'Deve responder 200 ao renovar sessão anônima expirada');
    const { csrfToken: token2 } = await res2.json();

    assert.ok(token2, 'Novo token CSRF deve estar presente');
    // O token deve ter mudado (nova sessão gerada)
    assert.notEqual(token1, token2, 'Token deve ser diferente após expiração da sessão anônima');

    // Restaura o tempo
    tempoSimulado = Date.now();
  });
});

describe('Expiração de sessão autenticada por inatividade (injeção de tempo)', () => {
  let ctx;
  let tempoSimulado = Date.now();
  const getNow = () => tempoSimulado;

  before(async () => {
    ctx = await criarAppDeTeste({ getNow });
    await criarUsuarioDeTeste(ctx.db, 'usuarioinat', 'SenhaCorreta123!');
  });
  after(async () => { await ctx.cleanup(); });

  test('Sessão autenticada expira após 30 minutos de inatividade', async () => {
    const { cookie } = await fazerLogin(ctx.baseUrl, 'usuarioinat', 'SenhaCorreta123!');

    // Avança 31 minutos sem nenhuma requisição (inatividade > 30 min)
    tempoSimulado += 31 * 60 * 1000;

    const res = await fetch(`${ctx.baseUrl}/api/dashboard`, {
      headers: { 'Cookie': cookie },
    });

    assert.equal(res.status, 401, 'Deve retornar 401 após 31 minutos de inatividade');

    tempoSimulado = Date.now();
  });

  test('Sessão é renovada com requisições antes de 30 minutos de inatividade', async () => {
    const { cookie } = await fazerLogin(ctx.baseUrl, 'usuarioinat', 'SenhaCorreta123!');

    // Avança 20 minutos (dentro da janela de 30 min) e faz requisição intermediária para renovar
    tempoSimulado += 20 * 60 * 1000;
    const resRenova = await fetch(`${ctx.baseUrl}/api/dashboard`, {
      headers: { 'Cookie': cookie },
    });
    assert.equal(resRenova.status, 200, 'Requisição em 20 min deve manter a sessão ativa');

    // Avança mais 20 minutos (total 40 min desde login, mas apenas 20 min desde última requisição)
    tempoSimulado += 20 * 60 * 1000;
    const resSucesso = await fetch(`${ctx.baseUrl}/api/dashboard`, {
      headers: { 'Cookie': cookie },
    });
    assert.equal(resSucesso.status, 200, 'Deve continuar autenticado devido à renovação');

    tempoSimulado = Date.now();
  });
});

describe('Expiração absoluta de 8 horas (injeção de tempo)', () => {
  let ctx;
  let tempoSimulado = Date.now();
  const getNow = () => tempoSimulado;

  before(async () => {
    ctx = await criarAppDeTeste({ getNow });
    await criarUsuarioDeTeste(ctx.db, 'usuario8h', 'SenhaCorreta123!');
  });
  after(async () => { await ctx.cleanup(); });

  test('A duração máxima absoluta de 8 horas é respeitada mesmo com renovações contínuas', async () => {
    const { cookie } = await fazerLogin(ctx.baseUrl, 'usuario8h', 'SenhaCorreta123!');

    // Simula requisições a cada 20 minutos durante 7 horas e 40 minutos (23 iterações)
    for (let i = 0; i < 23; i++) {
      tempoSimulado += 20 * 60 * 1000;
      const resAtiva = await fetch(`${ctx.baseUrl}/api/me`, {
        headers: { 'Cookie': cookie },
      });
      assert.equal(resAtiva.status, 200, `Requisição na marca de ${20 * (i + 1)} min deve responder 200`);
    }

    // Avança mais 30 minutos (tempo total decorrido: 8h10min > 8h absolutas)
    tempoSimulado += 30 * 60 * 1000;

    const resExpirada = await fetch(`${ctx.baseUrl}/api/me`, {
      headers: { 'Cookie': cookie },
    });
    assert.equal(resExpirada.status, 401, 'Deve retornar 401 obrigatoriamente após 8h absolutas');

    tempoSimulado = Date.now();
  });
});

describe('Rotação de token CSRF', () => {
  let ctx;

  before(async () => {
    ctx = await criarAppDeTeste();
    await criarUsuarioDeTeste(ctx.db, 'usuariocsrf', 'SenhaCorreta123!');
  });
  after(async () => { await ctx.cleanup(); });

  test('Token CSRF muda após login', async () => {
    const { csrfToken: tokenAntes, cookie: cookieAntes } = await obterCsrfECookie(ctx.baseUrl);

    // Faz login
    const resLogin = await fetch(`${ctx.baseUrl}/api/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': tokenAntes,
        'Cookie': cookieAntes,
      },
      body: JSON.stringify({ username: 'usuariocsrf', password: 'SenhaCorreta123!' }),
    });
    const cookiePos = resLogin.headers.get('set-cookie') ?? cookieAntes;

    // Obtém token após login
    const resNovoToken = await fetch(`${ctx.baseUrl}/api/csrf`, {
      headers: { 'Cookie': cookiePos },
    });
    const { csrfToken: tokenDepois } = await resNovoToken.json();

    assert.notEqual(tokenAntes, tokenDepois, 'Token CSRF deve mudar após login');
  });

  test('Token CSRF muda após logout', async () => {
    const { cookie, csrfToken: tokenPos } = await fazerLogin(ctx.baseUrl, 'usuariocsrf', 'SenhaCorreta123!');

    // Faz logout
    await fetch(`${ctx.baseUrl}/api/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': tokenPos,
        'Cookie': cookie,
      },
      body: JSON.stringify({}),
    });

    // Obtém novo token após logout (nova sessão anônima)
    const resNovoToken = await fetch(`${ctx.baseUrl}/api/csrf`);
    const { csrfToken: tokenAposLogout } = await resNovoToken.json();

    assert.notEqual(tokenPos, tokenAposLogout, 'Token CSRF deve mudar após logout');
  });
});

describe('Rate limit não penaliza login bem-sucedido', () => {
  let ctx;

  before(async () => {
    ctx = await criarAppDeTeste();
    await criarUsuarioDeTeste(ctx.db, 'usuariosucesso', 'SenhaCorreta123!');
  });
  after(async () => { await ctx.cleanup(); });

  test('Login bem-sucedido não consome o limite de falhas', async () => {
    // Faz 4 logins bem-sucedidos (não devem contar para o rate limit de falhas)
    for (let i = 0; i < 6; i++) {
      const { csrfToken, cookie } = await obterCsrfECookie(ctx.baseUrl);
      const res = await fetch(`${ctx.baseUrl}/api/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
          'Cookie': cookie,
        },
        body: JSON.stringify({ username: 'usuariosucesso', password: 'SenhaCorreta123!' }),
      });
      assert.equal(res.status, 200, `Login ${i + 1} bem-sucedido deve retornar 200`);
    }

    // A 5ª tentativa com senha errada deve passar (não atingiu o limite ainda)
    const { csrfToken, cookie } = await obterCsrfECookie(ctx.baseUrl);
    const resFalha = await fetch(`${ctx.baseUrl}/api/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Cookie': cookie,
      },
      body: JSON.stringify({ username: 'usuariosucesso', password: 'SenhaErrada!' }),
    });

    // Deve ser 401, não 429 (pois logins bem-sucedidos não contam)
    assert.equal(resFalha.status, 401, 'Deve retornar 401, não 429');
  });
});

describe('Rate limit não penaliza requisições com CSRF inválido (403)', () => {
  let ctx;

  before(async () => {
    ctx = await criarAppDeTeste();
    await criarUsuarioDeTeste(ctx.db, 'usuariocsrf403', 'SenhaCorreta123!');
  });
  after(async () => { await ctx.cleanup(); });

  test('5 requisições com CSRF inválido (403) não consomem o limite de falhas de login', async () => {
    // Envia 5 requisições POST com token CSRF inválido (recebendo 403)
    for (let i = 0; i < 5; i++) {
      const res403 = await fetch(`${ctx.baseUrl}/api/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': 'token-invalido-que-retorna-403',
        },
        body: JSON.stringify({ username: 'usuariocsrf403', password: 'SenhaQualquer!' }),
      });
      assert.equal(res403.status, 403, 'Requisição sem token CSRF válido deve retornar 403');
    }

    // A 6ª requisição com CSRF válido mas senha incorreta DEVE retornar 401 (e NÃO 429),
    // provando que as respostas 403 não consumiram o limite de 5 falhas de login.
    const { csrfToken, cookie } = await obterCsrfECookie(ctx.baseUrl);
    const resAuth = await fetch(`${ctx.baseUrl}/api/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Cookie': cookie,
      },
      body: JSON.stringify({ username: 'usuariocsrf403', password: 'SenhaIncorreta!' }),
    });

    assert.equal(resAuth.status, 401, 'Deve retornar 401 e não 429');
    const corpo = await resAuth.json();
    assert.equal(corpo.erro, 'Usuário ou senha inválidos');
  });
});

describe('Rate limit não penaliza requisições com Content-Type incorreto (415)', () => {
  let ctx;

  before(async () => {
    ctx = await criarAppDeTeste();
    await criarUsuarioDeTeste(ctx.db, 'usuario415', 'SenhaCorreta123!');
  });
  after(async () => { await ctx.cleanup(); });

  test('5 requisições com Content-Type incorreto (415) não consomem o limite de falhas de login', async () => {
    const { csrfToken, cookie } = await obterCsrfECookie(ctx.baseUrl);

    // Envia 5 requisições com Content-Type incorreto (text/plain) recebendo 415
    for (let i = 0; i < 5; i++) {
      const res415 = await fetch(`${ctx.baseUrl}/api/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          'X-CSRF-Token': csrfToken,
          'Cookie': cookie,
        },
        body: 'username=usuario415&password=qualquer',
      });
      assert.equal(res415.status, 415, 'POST sem application/json deve retornar 415');
    }

    // A requisição seguinte com JSON válido e senha incorreta DEVE retornar 401 (e NÃO 429),
    // provando que respostas 415 não consumiram o limite de 5 falhas de login.
    const resAuth = await fetch(`${ctx.baseUrl}/api/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Cookie': cookie,
      },
      body: JSON.stringify({ username: 'usuario415', password: 'SenhaIncorreta!' }),
    });

    assert.equal(resAuth.status, 401, 'Deve retornar 401 e não 429');
    const corpo = await resAuth.json();
    assert.equal(corpo.erro, 'Usuário ou senha inválidos');
  });
});

describe('Hash fictício na inicialização', () => {
  test('Hash fictício é gerado com os parâmetros corretos do Argon2id', async () => {
    const hash = await obterDummyHash();
    assert.ok(typeof hash === 'string', 'Hash fictício deve ser uma string');
    assert.ok(hash.startsWith('$argon2id$'), 'Hash deve ser do tipo argon2id');
    assert.ok(hash.includes('m=19456'), 'Hash deve conter memoryCost=19456');
    assert.ok(hash.includes('t=2'), 'Hash deve conter timeCost=2');
    assert.ok(hash.includes('p=1'), 'Hash deve conter parallelism=1');
  });
});

describe('Rotas inexistentes da API', () => {
  let ctx;

  before(async () => { ctx = await criarAppDeTeste(); });
  after(async () => { await ctx.cleanup(); });

  test('GET /api/inexistente retorna 404 em JSON genérico e não atende front-end', async () => {
    const res = await fetch(`${ctx.baseUrl}/api/rota-inexistente-12345`);
    assert.equal(res.status, 404);
    const contentType = res.headers.get('content-type') ?? '';
    assert.ok(contentType.includes('application/json'), 'Deve responder em JSON');
    const corpo = await res.json();
    assert.equal(corpo.erro, 'Rota não encontrada.');
  });

  test('POST /api/inexistente retorna 404 em JSON genérico', async () => {
    const res = await fetch(`${ctx.baseUrl}/api/outra-rota-inexistente`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 404);
    const corpo = await res.json();
    assert.equal(corpo.erro, 'Rota não encontrada.');
  });
});
