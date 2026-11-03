# Secure by Design — Projeto Aplicado

Aplicação web desenvolvida com a filosofia **Secure by Design**, demonstrando controles e mitigações rigorosas alinhadas ao **OWASP Top 10:2025**. O back-end foi construído em **Node.js 22 (LTS)** com Express e banco de dados SQLite persistente via `better-sqlite3`.

---

## Como Rodar Localmente

Siga a sequência de passos abaixo para configurar e executar a aplicação no seu ambiente de desenvolvimento:

1. **Entrar na pasta `app`:**
   ```bash
   cd app
   ```

2. **Executar `npm install`:**
   ```bash
   npm install
   ```

3. **Criar o `.env` a partir do `.env.example`:**
   ```bash
   cp .env.example .env
   # No Windows PowerShell:
   # Copy-Item .env.example .env
   ```

4. **Configurar as variáveis de ambiente necessárias:**
   Abra o arquivo `.env` e configure o `SESSION_SECRET` com uma cadeia aleatória segura de no mínimo 32 caracteres (veja o comando gerador na seção de variáveis). Nunca insira dados de produção ou segredos reais em repositórios.

5. **Criar um usuário com `npm run create-user`:**
   ```bash
   npm run create-user
   ```
   O script solicitará interativamente o *username* (3 a 50 caracteres) e a senha (12 a 128 caracteres, com digitação oculta no terminal e confirmação).

6. **Iniciar o servidor com `npm run dev:server`:**
   ```bash
   npm run dev:server
   ```
   O servidor iniciará escutando exclusivamente em `127.0.0.1:3000` (ou na porta configurada), com reinício automático via `node --watch`.

7. **Executar os testes com `npm test`:**
   ```bash
   npm test
   ```
   Executa a suíte de testes unitários e de integração utilizando o executor nativo do Node 22 (`node:test`).

---

## Variáveis de Ambiente

Todas as configurações sensíveis e de infraestrutura são carregadas estritamente a partir do arquivo `.env` e validadas logo na inicialização do servidor.

| Variável | Obrigatória | Padrão | Propósito |
|---|:---:|:---:|---|
| `SESSION_SECRET` | **Sim** | *Nenhum* | Chave criptográfica usada para assinar o cookie de sessão (`sid`). Deve conter **no mínimo 32 caracteres**. Se ausente ou menor que 32 caracteres, a aplicação aborta a inicialização imediatamente. |
| `PORT` | Não | `3000` | Porta TCP em que o servidor Express escuta (sempre vinculado exclusivamente à interface `127.0.0.1`). |
| `NODE_ENV` | Não | `development` | Ambiente de execução (`development`, `test` ou `production`). Quando `production`, ativa flags obrigatórias como cookie `Secure` e cabeçalho `HSTS`. |
| `DATABASE_PATH` | Não | `../data/app.db` | Caminho do arquivo de banco de dados SQLite. Permite isolamento determinístico para bancos temporários durante os testes. |

> [!IMPORTANT]
> A chave `SESSION_SECRET` **não possui valor padrão inseguro (fallback)** no código. Você pode gerar uma chave segura executando:
> ```bash
> node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
> ```

---

## Tabela OWASP Top 10:2025

Relação direta entre as categorias de segurança do OWASP Top 10:2025, os arquivos e funções responsáveis e a respectiva mitigação implementada no código:

| Categoria OWASP | Onde está no código (arquivo e função) | Como é mitigada |
|---|---|---|
| **A01:2025 - Broken Access Control** | `server/src/middleware/auth.js` (`requireAuth`), `server/src/routes/me.js` e `server/src/routes/dashboard.js` | Exige sessão autenticada ativa (`userId` na sessão) para acesso às rotas `/api/me` e `/api/dashboard`, retornando HTTP 401 caso ausente. Aplica o cabeçalho `Cache-Control: no-store` em todas as respostas privadas para impedir armazenamento em cache compartilhado, proxies ou histórico de navegadores. |
| **A02:2025 - Security Misconfiguration** | `server/server.js` (`criarApp`), `server/src/config/env.js` (`carregarConfig`) e `server/src/middleware/contentType.js` (`validarContentType`) | Configura o Helmet com Content-Security-Policy (CSP) restritiva (sem scripts inline), desabilita o cabeçalho `x-powered-by`, define HSTS em produção sem preload, vincula a escuta estritamente a `127.0.0.1`, restringe o corpo JSON a 10 KB, valida as variáveis no boot sem fallbacks inseguros e rejeita requisições POST sem `Content-Type: application/json` com HTTP 415. Respostas de erro 404 e 500 retornam JSON genérico sem vazamento de stack trace. |
| **A03:2025 - Software Supply Chain Failures** | `package.json`, `package-lock.json` e políticas de build | Bloqueio de versões exatas com `package-lock.json` versionado no repositório, instalação reprodutível via `npm ci` / `npm install`, verificação contínua de vulnerabilidades de pacotes conhecidos via `npm audit` e uso exclusivo de dependências amplamente auditadas e ativamente mantidas pela comunidade. |
| **A04:2025 - Cryptographic Failures** | `server/src/routes/login.js` (`DUMMY_HASH`, `ARGON2_OPCOES`), `server/scripts/create-user.js` e `server/src/middleware/csrf.js` (`gerarToken`) | Uso exclusivo do algoritmo Argon2id com parâmetros robustos recomendados pelo OWASP (`memoryCost: 19456 KiB`, `timeCost: 2`, `parallelism: 1`). Nenhuma credencial ou senha trafega ou é gravada em texto puro. Geração de tokens CSRF a partir de gerador criptograficamente seguro (`crypto.randomBytes`). Emprego de verificação contra hash fictício na inicialização para equalizar o tempo de resposta e evitar timing attacks em credenciais inexistentes. |
| **A05:2025 - Injection** | `server/src/db/database.js` (`criarBancoDeDados`), `server/src/routes/login.js` e `server/scripts/create-user.js` | Consultas SQL 100% parametrizadas (uso de placeholders `?` no `better-sqlite3`), eliminando qualquer possibilidade de SQL Injection. Validação rigorosa de tipo, comprimento e formato para username e password, com normalização de strings (trim e minúsculas). |
| **A07:2025 - Authentication Failures** | `server/src/routes/login.js`, `server/src/routes/logout.js`, `server/src/routes/csrf.js` e `server/src/middleware/auth.js` | Mensagem de erro única e opaca (`"Usuário ou senha inválidos"`) para evitar enumeração de usuários. Limitação de taxa de força bruta com `express-rate-limit` restrita a 5 falhas (HTTP 401) por IP a cada 15 minutos (com bloqueio 429). Regeneração do ID de sessão no login (`req.session.regenerate`) contra Session Fixation. Destruição completa da sessão no servidor e limpeza do cookie no logout. Expiração estrita de sessão anônima em 15 minutos, inatividade autenticada de 30 minutos (renovável a cada requisição) e teto absoluto inegociável de 8 horas desde a criação da sessão. |
| **A09:2025 - Security Logging and Alerting Failures** | `server/src/routes/login.js` (`log`), `server/src/routes/logout.js` e `server/src/middleware/csrf.js` (`registrarLogCsrfInvalido`) | Registro estruturado em JSON com data/hora, tipo de evento (`login_sucesso`, `login_falha`, `logout`, `csrf_invalido`, `rate_limit`), IP e username truncado em 50 caracteres com caracteres de controle e quebras de linha removidos (evitando log injection / log forging). O sistema **nunca** registra senhas, hashes, tokens CSRF, cookies ou segredos. |

---

## Decisões de Segurança e Justificativas Técnicas

### 1. Store de Sessão: `better-sqlite3-session-store`
- **Compatibilidade nativa síncrona:** A aplicação utiliza o driver `better-sqlite3` por sua alta performance e confiabilidade. O pacote `better-sqlite3-session-store` interage diretamente com a instância aberta do banco de dados SQLite, eliminando a necessidade de gerenciar uma segunda conexão assíncrona concorrente (como faria o `connect-sqlite3`).
- **Limpeza de expiração persistente:** Suporta agendamento automático para purga física de sessões expiradas diretamente no banco a cada 15 minutos (`expired: { clear: true, intervalMs: 900000 }`), garantindo que o armazenamento persistente não sofra inchaço.
- **Segurança operacional:** Substitui com excelência o `MemoryStore` padrão do `express-session`, que vazaria memória e não sobreviveria a múltiplos workers ou reinicializações do processo.

### 2. Proteção contra Enumeração e Timing Attacks no Login
- Na tentativa de login de um usuário inexistente, o tempo de resposta seria ordens de grandeza menor que o tempo de verificação de um usuário existente (já que o Argon2id consome deliberadamente ~19 MiB e 2 iterações de CPU).
- Para equalizar essa diferença, a aplicação calcula um hash fictício (`DUMMY_HASH`) uma única vez durante a inicialização do módulo `login.js`. Se o usuário não for encontrado no banco de dados, o servidor ainda assim executa `argon2.verify(DUMMY_HASH, password)`. Dessa forma, o tempo computacional de resposta é indistinguível para credenciais existentes ou inexistentes.

### 3. Rate Limiting Focado Exclusivamente em Falhas de Autenticação
- O limitador em `POST /api/login` foi configurado com `requestWasSuccessful: (req, res) => res.statusCode !== 401`.
- Essa configuração garante que requisições com status 200 (login bem-sucedido), 500 (falhas operacionais de banco ou rede) ou 403 (CSRF ausente) **não** consumam a cota de 5 tentativas de autenticação do usuário legítimo. Apenas credenciais inválidas (HTTP 401) incrementam o contador de força bruta.

### 4. Ciclo de Vida e Expiração Multinível de Sessões
- **Sessões Anônimas:** Destinadas apenas ao fornecimento do token CSRF inicial para o formulário de login. Possuem vida útil de 15 minutos (`maxAge: 15 * 60 * 1000`). Se expiradas, são destruídas e regeradas pelo endpoint `GET /api/csrf`.
- **Sessões Autenticadas (Inatividade):** Duram 30 minutos a partir da última requisição. A cada requisição bem-sucedida a uma rota protegida, o middleware `requireAuth` atualiza `lastActivity` e renova o cookie para 30 minutos.
- **Sessões Autenticadas (Limite Absoluto de 8 Horas):** A hora de autenticação original é registrada no atributo `createdAt`. Mesmo que o usuário continue ativo continuamente enviando requisições a cada 5 minutos, o middleware `requireAuth` calcula o tempo restante `8h - (agora - createdAt)`. Ao completar 8 horas, a renovação é interrompida, a sessão é destruída no banco e o cliente é forçado a reautenticar.

---

## Fluxo Completo: Autenticação, CSRF, Sessões e Logout

```text
Cliente (Navegador / SPA)                         Servidor Express (127.0.0.1)
   |                                                         |
   |---- 1. GET /api/csrf ---------------------------------->| Cria sessão anônima (15 min)
   |                                                         | Gera token CSRF criptográfico
   |<--- 2. Responde 200 { csrfToken } + Cookie 'sid' -------|
   |                                                         |
   |---- 3. POST /api/login -------------------------------->| 1. Valida Content-Type (415 se não for JSON)
   |     Headers: Content-Type: application/json             | 2. Valida X-CSRF-Token via timingSafeEqual (403 se falhar)
   |              X-CSRF-Token: <token>                      | 3. Normaliza e valida campos (1-50 / 1-128 chars)
   |              Cookie: sid=<cookie>                       | 4. Busca usuário (query parametrizada)
   |     Body: { username, password }                        | 5. argon2.verify (ou DUMMY_HASH)
   |                                                         | 6. Falha: 401 "Usuário ou senha inválidos" (consome rate limit)
   |                                                         | 7. Sucesso: atualiza last_login_at no banco
   |                                                         | 8. req.session.regenerate() (novo sid)
   |                                                         | 9. Salva userId, createdAt e previousLogin
   |                                                         | 10. Gera NOVO token CSRF
   |<--- 4. Responde 200 { username } + NOVO Cookie 'sid' ---| Log: login_sucesso (JSON estruturado)
   |                                                         |
   |---- 5. GET /api/dashboard ----------------------------->| requireAuth verifica:
   |     Headers: Cookie: sid=<cookie>                       | - userId presente na sessão?
   |                                                         | - decorrido > 8 horas absolutas? (401 se expirado)
   |                                                         | - inativo > 30 minutos? (401 se expirado)
   |                                                         | - Renova inatividade (mín(30min, tempo restante de 8h))
   |<--- 6. Responde 200 { mensagem, username, ultimoLogin } | Cache-Control: no-store
   |                                                         |
   |---- 7. POST /api/logout ------------------------------->| 1. Valida Content-Type e X-CSRF-Token
   |     Headers: X-CSRF-Token: <token>                      | 2. req.session.destroy() no SQLite
   |              Cookie: sid=<cookie>                       | 3. res.clearCookie('sid')
   |<--- 8. Responde 204 No Content -------------------------| Log: logout (JSON estruturado)
```
