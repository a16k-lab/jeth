(() => {
  const root = document.documentElement;
  const siteRoot = new URL('../', document.currentScript.src);
  const storedTheme = localStorage.getItem('jeth-docs-theme');
  if (storedTheme) root.dataset.theme = storedTheme;

  document.querySelector('.theme-toggle')?.addEventListener('click', () => {
    const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
    root.dataset.theme = next;
    localStorage.setItem('jeth-docs-theme', next);
  });

  document.querySelector('.menu-toggle')?.addEventListener('click', () => document.body.classList.toggle('nav-open'));
  document.querySelectorAll('.sidebar-link').forEach((link) => link.addEventListener('click', () => document.body.classList.remove('nav-open')));

  document.querySelectorAll('.copy-code').forEach((button) => {
    button.addEventListener('click', async () => {
      const code = button.closest('.code-block')?.querySelector('code')?.textContent || '';
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(code);
      } else {
        const area = document.createElement('textarea');
        area.value = code;
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.append(area);
        area.select();
        document.execCommand('copy');
        area.remove();
      }
      button.textContent = 'Copied';
      setTimeout(() => { button.textContent = 'Copy'; }, 1200);
    });
  });

  const modal = document.querySelector('.search-modal');
  const input = document.querySelector('.search-input');
  const results = document.querySelector('.search-results');
  const searchIndex = window.JETH_SEARCH_INDEX || [];
  const escapeMarkup = (value) => String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
  const openSearch = () => { modal.hidden = false; setTimeout(() => input.focus(), 0); };
  const closeSearch = () => { modal.hidden = true; input.value = ''; results.innerHTML = '<div class="search-empty">Start typing to search the book.</div>'; };
  document.querySelector('.search-trigger')?.addEventListener('click', openSearch);
  document.querySelector('.search-close')?.addEventListener('click', closeSearch);
  document.querySelector('.search-backdrop')?.addEventListener('click', closeSearch);
  document.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); openSearch(); }
    if (event.key === 'Escape' && !modal.hidden) closeSearch();
  });
  input?.addEventListener('input', () => {
    const query = input.value.trim().toLowerCase();
    if (!query) { results.innerHTML = '<div class="search-empty">Start typing to search the book.</div>'; return; }
    const terms = query.split(/\s+/);
    const matches = searchIndex.filter((item) => terms.every((term) => (item.title + ' ' + item.group + ' ' + item.text).toLowerCase().includes(term))).slice(0, 12);
    results.innerHTML = matches.length ? matches.map((item) => '<a class="search-result" href="' + new URL(item.path, siteRoot).href + '"><strong>' + escapeMarkup(item.title) + '</strong><span>' + escapeMarkup(item.group) + ' · ' + escapeMarkup(item.text.slice(0, 150)) + '</span></a>').join('') : '<div class="search-empty">No matching guide found.</div>';
  });
})();
