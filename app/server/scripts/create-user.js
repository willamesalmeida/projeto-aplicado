'use strict';

/**
 * Script interativo para criar usuários no banco de dados.
 * Deve ser executado via terminal: npm run create-user
 *
 * OWASP A04:2025 - Cryptographic Failures:
 * Utiliza o algoritmo Argon2id com parâmetros robustos (memoryCost: 19456 KiB, timeCost: 2, parallelism: 1).
 * Nunca expõe senhas em texto puro nem os hashes gerados.
 *
 * OWASP A05:2025 - Injection:
 * Normaliza o username (trim e minúsculas), valida com regex estrito e executa inserção
 * no SQLite exclusivamente via queries parametrizadas.
 */

const readline = require('readline');
const path = require('path');

// Carrega configuração (validará SESSION_SECRET se presente, mas aqui não é obrigatório)
// Para este script, apenas precisamos do DATABASE_PATH
const dotenv = require('dotenv');
dotenv.config({ path: path.resolve(__dirname, '..', '..', '..', '.env') });

const { criarBancoDeDados } = require('../src/db/database');
const argon2 = require('argon2');

// Parâmetros Argon2id recomendados
const ARGON2_OPCOES = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

// Regex para username válido: letras, números, ponto, hífen, sublinhado
const REGEX_USERNAME = /^[a-z0-9._-]+$/;

/**
 * Lê uma linha do terminal sem exibir o que é digitado (modo senha).
 *
 * @param {string} pergunta - Texto exibido antes da entrada.
 * @returns {Promise<string>} Texto digitado pelo usuário.
 */
function lerSenhaOculta(pergunta) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });

    process.stdout.write(pergunta);

    let senha = '';

    // Tenta usar modo raw para ocultar entrada (TTY)
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.setEncoding('utf8');

      const handler = (ch) => {
        if (ch === '\n' || ch === '\r' || ch === '\u0003') {
          // Enter ou Ctrl+C
          if (ch === '\u0003') {
            process.stdout.write('\n');
            process.stdin.setRawMode(false);
            process.stdin.removeListener('data', handler);
            rl.close();
            process.exit(0);
          }
          process.stdout.write('\n');
          process.stdin.setRawMode(false);
          process.stdin.removeListener('data', handler);
          rl.close();
          resolve(senha);
        } else if (ch === '\u007f' || ch === '\b') {
          // Backspace
          if (senha.length > 0) {
            senha = senha.slice(0, -1);
          }
        } else {
          senha += ch;
        }
      };

      process.stdin.on('data', handler);
    } else {
      // Fallback para ambientes sem TTY
      rl.question('', (resposta) => {
        rl.close();
        resolve(resposta);
      });
    }
  });
}

/**
 * Lê uma linha comum do terminal.
 *
 * @param {string} pergunta - Texto exibido antes da entrada.
 * @returns {Promise<string>}
 */
function lerEntrada(pergunta) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(pergunta, (resposta) => {
      rl.close();
      resolve(resposta);
    });
  });
}

async function main() {
  console.log('=== Criação de usuário ===\n');

  // Lê e valida o username
  const usernameRaw = await lerEntrada('Username (3-50 chars, letras/números/ponto/hífen/sublinhado): ');
  const username = usernameRaw.trim().toLowerCase();

  if (username.length < 3 || username.length > 50) {
    console.error('Erro: username deve ter entre 3 e 50 caracteres.');
    process.exit(1);
  }

  if (!REGEX_USERNAME.test(username)) {
    console.error('Erro: username contém caracteres inválidos. Use apenas letras, números, ponto, hífen ou sublinhado.');
    process.exit(1);
  }

  // Lê senha duas vezes para confirmação
  const senha1 = await lerSenhaOculta('Senha (12-128 chars): ');

  if (senha1.length < 12 || senha1.length > 128) {
    console.error('Erro: a senha deve ter entre 12 e 128 caracteres.');
    // NUNCA imprime a senha
    process.exit(1);
  }

  const senha2 = await lerSenhaOculta('Confirme a senha: ');

  if (senha1 !== senha2) {
    console.error('Erro: as senhas não coincidem.');
    // NUNCA imprime as senhas
    process.exit(1);
  }

  // Inicializa o banco de dados
  const dbPath = process.env.DATABASE_PATH ?? path.resolve(__dirname, '..', '..', 'data', 'app.db');
  let db;
  try {
    db = criarBancoDeDados(dbPath);
  } catch {
    console.error('Erro ao conectar ao banco de dados.');
    process.exit(1);
  }

  // Verifica se o usuário já existe
  try {
    const existente = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existente) {
      console.error(`Erro: o usuário "${username}" já existe.`);
      process.exit(1);
    }
  } catch {
    console.error('Erro ao verificar usuário no banco.');
    process.exit(1);
  }

  // Gera o hash Argon2id
  // NUNCA imprime a senha nem o hash
  let hash;
  try {
    console.log('\nGerando hash seguro da senha...');
    hash = await argon2.hash(senha1, ARGON2_OPCOES);
  } catch {
    console.error('Erro ao gerar hash da senha.');
    process.exit(1);
  }

  // Insere o usuário no banco com query parametrizada
  // OWASP A05:2025 - Query parametrizada
  try {
    db.prepare(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)'
    ).run(username, hash);
  } catch {
    console.error('Erro ao salvar o usuário no banco.');
    process.exit(1);
  }

  console.log(`\nUsuário "${username}" criado com sucesso.`);
  db.close();
}

main().catch(() => {
  console.error('Ocorreu um erro inesperado. O usuário pode não ter sido criado.');
  process.exit(1);
});

