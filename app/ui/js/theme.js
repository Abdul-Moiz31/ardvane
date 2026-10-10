// @ts-check
// Light / dark theme. Loaded as a plain script in <head> so the right colours apply before the page is drawn.
// The choice ("system", "light" or "dark") is a per-computer convenience kept in localStorage; "system" follows the OS.
(function () {
  const KEY = 'guard-theme';
  const media = window.matchMedia('(prefers-color-scheme: dark)');

  function stored() {
    try { return localStorage.getItem(KEY) || 'system'; } catch (e) { return 'system'; }
  }

  function apply(choice) {
    const dark = choice === 'dark' || (choice === 'system' && media.matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    document.documentElement.dataset.themeChoice = choice;
  }

  apply(stored());
  media.addEventListener('change', () => apply(stored()));

  /** @type {any} */ (window).guardTheme = {
    get: stored,
    /** @param {'system'|'light'|'dark'} choice */
    set(choice) {
      try { localStorage.setItem(KEY, choice); } catch (e) { /* still applied for this page */ }
      apply(choice);
    },
  };
})();
