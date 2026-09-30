fetch('/api/me', {credentials: 'same-origin', cache: 'no-store'})
  .then((response) => response.ok ? response.json() : null)
  .then((user) => {
    const status = document.getElementById('status');
    status.textContent = user ? `Sessão de ${user.email ?? user.displayName ?? user.subject}.` : 'Nenhuma sessão neste navegador.';
  })
  .catch(() => { document.getElementById('status').textContent = 'Não foi possível consultar a sessão.'; });
