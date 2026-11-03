'use strict';

/**
 * Módulo de conexão com o banco de dados SQLite via better-sqlite3.
 * Cria o diretório app/data/ e a tabela users caso não existam.
 *
 * OWASP A05:2025 - Injection:
 * Todas as operações no banco utilizam consultas 100% parametrizadas (placeholders ?),
 * sem concatenação de strings ou interpolação de dados de entrada, prevenindo injeção de SQL.
 */

const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

/**
 * Cria e configura uma instância do banco de dados SQLite.
 *
 * @param {string} dbPath - Caminho absoluto para o arquivo do banco de dados.
 * @returns {Database} Instância configurada do banco de dados.
 */
function criarBancoDeDados(dbPath) {
  // Garante que o diretório de dados existe antes de tentar abrir o banco
  const dir = path.dirname(dbPath);
  fs.mkdirSync(dir, { recursive: true });

  const db = new Database(dbPath);

  // Habilita WAL mode para melhor performance em leituras concorrentes
  db.pragma('journal_mode = WAL');

  // Habilita chaves estrangeiras (boa prática de integridade)
  db.pragma('foreign_keys = ON');

  /**
   * Tabela de usuários.
   * OWASP A05:2025 - Injection:
   * Coluna username definida com COLLATE NOCASE para comparação case-insensitive uniforme.
   */
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE COLLATE NOCASE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_login_at TEXT
    )
  `);

  return db;
}

module.exports = { criarBancoDeDados };

