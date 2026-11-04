import { useCallback, useEffect, useState } from 'react';
import { obterDashboard, entrar, sair } from './api.js';

// O servidor grava a data em UTC, no formato "AAAA-MM-DD HH:MM:SS", sem fuso.
function formatarData(valor) {
    if (!valor) return 'primeiro acesso';
    let texto = String(valor).replace(' ', 'T');
    if (!texto.endsWith('Z')) texto += 'Z';
    const data = new Date(texto);
    if (Number.isNaN(data.getTime())) return 'indisponível';
    return data.toLocaleString('pt-BR');
}

export default function App() {
    const [tela, setTela] = useState('carregando');
    const [usuario, setUsuario] = useState(null);
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [erro, setErro] = useState('');
    const [enviando, setEnviando] = useState(false);

    const verificarSessao = useCallback(async () => {
        try {
            const { status, dados } = await obterDashboard();
            if (status === 200 && dados) {
                setUsuario(dados);
                setTela('interna');
            } else {
                setUsuario(null);
                setTela('login');
            }
        } catch {
            setUsuario(null);
            setTela('login');
            setErro('Não foi possível falar com o servidor.');
        }
    }, []);

    useEffect(() => {
        verificarSessao();
        // Ao voltar com o botão Voltar, o navegador pode restaurar a página
        // antiga; por isso a sessão é conferida de novo.
        const aoMostrar = (evento) => {
            if (evento.persisted) verificarSessao();
        };
        window.addEventListener('pageshow', aoMostrar);
        return () => window.removeEventListener('pageshow', aoMostrar);
    }, [verificarSessao]);

    async function aoEnviarLogin(evento) {
        evento.preventDefault();
        if (enviando) return;
        setEnviando(true);
        setErro('');
        try {
            const r = await entrar(username.trim(), password);
            setPassword('');
            if (r.ok) {
                setUsername('');
                await verificarSessao();
            } else if (r.status === 429) {
                setErro('Muitas tentativas. Tente novamente em 15 minutos.');
            } else if (r.status === 401) {
                setErro('Usuário ou senha inválidos.');
            } else {
                setErro('Não foi possível entrar. Tente novamente.');
            }
        } catch {
            setPassword('');
            setErro('Não foi possível falar com o servidor.');
        } finally {
            setEnviando(false);
        }
    }

    async function aoSair() {
        try {
            await sair();
        } catch {
            // Se falhar, a checagem abaixo mostra o estado real da sessão.
        }
        setUsername('');
        setPassword('');
        setErro('');
        await verificarSessao();
    }

    if (tela === 'carregando') {
        return (
            <main className="pagina">
                <p>Carregando…</p>
            </main>
        );
    }

    if (tela === 'interna' && usuario) {
        return (
            <main className="pagina">
                <header className="topo">
                    <button type="button" className="botao-sair" onClick={aoSair}>
                        Sair
                    </button>
                </header>
                <section className="cartao">
                    <h1>Olá, {usuario.username}</h1>
                    <p>{usuario.mensagem}</p>
                    <p className="detalhe">
                        Último acesso: {formatarData(usuario.ultimoLogin)}
                    </p>
                </section>
            </main>
        );
    }

    return (
        <main className="pagina">
            <section className="cartao">
                <h1>Entrar</h1>
                <form onSubmit={aoEnviarLogin}>
                    <label htmlFor="username">Usuário</label>
                    <input
                        id="username"
                        name="username"
                        type="text"
                        autoComplete="username"
                        maxLength={50}
                        required
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                    />
                    <label htmlFor="password">Senha</label>
                    <input
                        id="password"
                        name="password"
                        type="password"
                        autoComplete="current-password"
                        maxLength={128}
                        required
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                    />
                    {erro && (
                        <p className="erro" role="alert">
                            {erro}
                        </p>
                    )}
                    <button type="submit" disabled={enviando}>
                        {enviando ? 'Entrando…' : 'Entrar'}
                    </button>
                </form>
            </section>
        </main>
    );
}