'use strict';

/**
 * Módulo de configuração e validação de variáveis de ambiente.
 *
 * OWASP A02:2025 - Security Misconfiguration:
 * Valida estritamente todas as configurações críticas na inicialização da aplicação.
 * SESSION_SECRET é estritamente obrigatório, requer no mínimo 32 caracteres e não
 * possui valor padrão ou fallback silencioso e inseguro. Se inválido, o processo é abortado.
 */

const path = require('path');
const dotenv = require('dotenv');

// Carrega o arquivo .env do diretório pai (app/)
dotenv.config({ path: path.resolve(__dirname, '..', '..', '..', '.env') });

/**
 * Valida e retorna as configurações do ambiente.
 * Lança um erro e encerra o processo se variáveis obrigatórias estiverem ausentes
 * ou inválidas.
 *
 * @param {object} [overrides] - Sobrescritas para uso em testes (ex: { sessionSecret, port })
 * @returns {object} Objeto de configuração validado
 */
function carregarConfig(overrides = {}) {
  // OWASP A02:2025 - Security Misconfiguration:
  // SESSION_SECRET: obrigatório, mínimo 32 caracteres, sem valor padrão
  const sessionSecret = overrides.sessionSecret ?? process.env.SESSION_SECRET;
  if (!sessionSecret) {
    throw new Error(
      '[Config] SESSION_SECRET é obrigatório. ' +
      'Defina-o no arquivo .env com pelo menos 32 caracteres.'
    );
  }
  if (sessionSecret.length < 32) {
    throw new Error(
      `[Config] SESSION_SECRET deve ter pelo menos 32 caracteres (atual: ${sessionSecret.length}).`
    );
  }

  // PORT: opcional, padrão 3000
  const portaEnv = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  const port = overrides.port ?? portaEnv;

  // NODE_ENV: opcional, padrão 'development'
  const nodeEnv = overrides.nodeEnv ?? process.env.NODE_ENV ?? 'development';

  // DATABASE_PATH: opcional, padrão relativo ao server.js
  const databasePath =
    overrides.databasePath ??
    process.env.DATABASE_PATH ??
    path.resolve(__dirname, '..', '..', '..', 'data', 'app.db');

  return {
    sessionSecret,
    port,
    nodeEnv,
    databasePath,
    isProduction: nodeEnv === 'production',
  };
}

module.exports = { carregarConfig };
