/**
 * BuildToValue Trust OS — Theme Controller
 * Fundamentação: Gilligan (Acessibilidade), Rawls (Equidade de acesso visual)
 *
 * Mecanismo: dataset.theme no <html> — compatível com [data-theme="light"]
 * já definido em btv.css. NÃO usar classList para não conflitar.
 */

(function () {
  'use strict';

  const STORAGE_KEY = 'btv-theme';
  const DEFAULT     = 'dark';

  function getTheme() {
    try { return localStorage.getItem(STORAGE_KEY) || DEFAULT; } catch { return DEFAULT; }
  }

  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(STORAGE_KEY, theme); } catch {}
    // Atualizar ícone do botão se existir (emoji fallback)
    const btn = document.getElementById('theme-toggle-btn');
    if (btn) btn.textContent = theme === 'light' ? '🌙' : '☀️';
    // Suporte ao par de SVGs moon/sun usado na navbar global
    const moon = document.getElementById('t-moon');
    const sun  = document.getElementById('t-sun');
    if (moon && sun) {
      moon.style.display = theme === 'light' ? 'block' : 'none';
      sun.style.display  = theme === 'light' ? 'none'  : 'block';
    }
    console.info(`[BTV Governance] Tema: ${theme.toUpperCase()}`);
  }

  // Aplicar IMEDIATAMENTE (antes do DOMContentLoaded) para evitar FOUC
  setTheme(getTheme());

  // Expor globalmente para o botão no header
  window.toggleRepublicTheme = function () {
    const current = document.documentElement.dataset.theme || DEFAULT;
    setTheme(current === 'light' ? 'dark' : 'light');
  };
  // Alias para compatibilidade com onclick="toggleTheme()" na navbar global
  window.toggleTheme = window.toggleRepublicTheme;

  // Re-sincronizar ícones após DOM pronto
  document.addEventListener('DOMContentLoaded', () => {
    const theme = getTheme();
    const btn  = document.getElementById('theme-toggle-btn');
    if (btn) btn.textContent = theme === 'light' ? '🌙' : '☀️';
    const moon = document.getElementById('t-moon');
    const sun  = document.getElementById('t-sun');
    if (moon && sun) {
      moon.style.display = theme === 'light' ? 'block' : 'none';
      sun.style.display  = theme === 'light' ? 'none'  : 'block';
    }
  });
})();
