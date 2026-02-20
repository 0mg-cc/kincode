/**
 * Simple i18n module
 * Supports dynamic loading and browser language detection
 */

const I18n = {
  translations: {},
  currentLang: 'fr',
  supportedLangs: ['fr', 'en', 'es'],
  
  async init() {
    const browserLang = navigator.language.slice(0, 2);
    const savedLang = this.getStoredLang();
    const lang = savedLang || (this.supportedLangs.includes(browserLang) ? browserLang : 'fr');
    await this.setLang(lang);
  },

  getStoredLang() {
    try {
      return localStorage.getItem('kincode-lang');
    } catch (e) {
      console.warn('Language preference unavailable:', e);
      return null;
    }
  },

  setStoredLang(lang) {
    try {
      localStorage.setItem('kincode-lang', lang);
    } catch (e) {
      console.warn('Failed to persist language preference:', e);
    }
  },

  async loadTranslations(lang) {
    if (this.translations[lang]) return this.translations[lang];
    
    try {
      const response = await fetch(`/js/translations/${lang}.json`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      this.translations[lang] = await response.json();
      return this.translations[lang];
    } catch (e) {
      console.error(`Failed to load ${lang} translations:`, e);
      if (lang !== 'fr') return this.loadTranslations('fr');
      return {};
    }
  },

  async setLang(lang) {
    if (!this.supportedLangs.includes(lang)) lang = 'fr';
    await this.loadTranslations(lang);
    this.currentLang = lang;
    this.setStoredLang(lang);
    document.documentElement.lang = lang;
    this.updateDOM();
  },

  t(key) {
    const keys = key.split('.');
    let value = this.translations[this.currentLang];
    for (const k of keys) {
      if (value === undefined) return key;
      value = value[k];
    }
    return value || key;
  },

  updateDOM() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      el.textContent = this.t(key);
    });
    
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      const key = el.getAttribute('data-i18n-placeholder');
      el.placeholder = this.t(key);
    });
    
    document.querySelectorAll('[data-i18n-aria]').forEach(el => {
      const key = el.getAttribute('data-i18n-aria');
      el.setAttribute('aria-label', this.t(key));
    });

    document.querySelectorAll('[data-i18n-content]').forEach(el => {
      const key = el.getAttribute('data-i18n-content');
      el.setAttribute('content', this.t(key));
    });

    // Update lang selector
    const langSelect = document.getElementById('lang-select');
    if (langSelect) langSelect.value = this.currentLang;
  }
};

export default I18n;
