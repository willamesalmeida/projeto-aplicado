// Comunicação com a API. O token CSRF fica só em memória (nunca em storage).

async function buscarTokenCsrf() {
    const resp = await fetch('/api/csrf', {
        credentials: 'same-origin',
        cache: 'no-store',
    });
    if (!resp.ok) {
        throw new Error('Falha ao obter o token de segurança.');
    }
    const dados = await resp.json();
    return dados.csrfToken;
}

async function enviarPost(caminho, corpo) {
    const token = await buscarTokenCsrf();
    return fetch(caminho, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': token,
        },
        body: JSON.stringify({ ...corpo, csrfToken: token }),
    });
}

async function lerJson(resp) {
    try {
        return await resp.json();
    } catch {
        return null;
    }
}

// 200 = autenticado (dados com username e ultimoLogin); 401 = não autenticado.
export async function obterDashboard() {
    const resp = await fetch('/api/dashboard', {
        credentials: 'same-origin',
        cache: 'no-store',
    });
    const dados = resp.ok ? await lerJson(resp) : null;
    return { status: resp.status, dados };
}

export async function entrar(username, password) {
    const resp = await enviarPost('/api/login', { username, password });
    const dados = await lerJson(resp);
    return { ok: resp.ok, status: resp.status, dados };
}

export async function sair() {
    const resp = await enviarPost('/api/logout', {});
    return { ok: resp.ok, status: resp.status };
}