import I18n from './i18n.js';
import TOTP from './totp.js';

const App = {
  currentSecret: null,
  members: [],
  demoInterval: null,
  MIN_MEMBERS: 2,
  MAX_MEMBERS: 12,

  async init() {
    await I18n.init();
    this.initMembers();
    this.bindEvents();
    this.checkReducedMotion();
  },

  initMembers() {
    // Start with 2 members
    this.members = [
      { id: 1, name: '' },
      { id: 2, name: '' }
    ];
    this.renderMemberInputs();
  },

  bindEvents() {
    // Language selector
    document.getElementById('lang-select')?.addEventListener('change', async (e) => {
      await I18n.setLang(e.target.value);
      this.renderMemberInputs();
      if (this.currentSecret) this.updateResults();
    });

    // Form submission
    document.getElementById('generate-form')?.addEventListener('submit', (e) => {
      e.preventDefault();
      this.generate();
    });

    // Add member button
    document.getElementById('add-member')?.addEventListener('click', () => {
      this.addMember();
    });

    // Copy buttons and remove member (delegated)
    document.addEventListener('click', (e) => {
      if (e.target.matches('[data-copy]')) {
        this.copyToClipboard(e.target);
      }
      if (e.target.matches('.remove-member') || e.target.closest('.remove-member')) {
        const btn = e.target.closest('.remove-member');
        const id = parseInt(btn.dataset.memberId);
        this.removeMember(id);
      }
    });

    // Toggle manual entry
    document.addEventListener('click', (e) => {
      if (e.target.matches('.toggle-manual') || e.target.closest('.toggle-manual')) {
        const btn = e.target.closest('.toggle-manual');
        const details = btn.closest('.qr-card').querySelector('.manual-details');
        details.hidden = !details.hidden;
        btn.setAttribute('aria-expanded', !details.hidden);
      }
    });

    // Member name inputs (delegated)
    document.addEventListener('input', (e) => {
      if (e.target.matches('.member-name-input')) {
        const id = parseInt(e.target.dataset.memberId);
        const member = this.members.find(m => m.id === id);
        if (member) member.name = e.target.value;
        this.clearFieldError(id);
      }
    });
  },

  checkReducedMotion() {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      document.documentElement.classList.add('reduce-motion');
    }
  },

  escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[char]));
  },

  renderMemberInputs() {
    const container = document.getElementById('members-container');
    if (!container) return;

    container.innerHTML = this.members.map((member, index) => {
      const safeName = this.escapeHtml(member.name);
      return `
      <div class="member-input-block" data-member-id="${member.id}">
        <div class="member-input-row">
          <label for="member-${member.id}" class="sr-only">
            ${I18n.t('form.namePlaceholder')} ${index + 1}
          </label>
          <input
            type="text"
            id="member-${member.id}"
            class="member-name-input"
            name="member-${member.id}"
            data-member-id="${member.id}"
            value="${safeName}"
            placeholder="${I18n.t('form.namePlaceholder')} ${index + 1}"
            autocomplete="off"
            required
          >
          ${this.members.length > this.MIN_MEMBERS ? `
            <button type="button" class="btn btn-icon remove-member" data-member-id="${member.id}" 
                    aria-label="${I18n.t('form.removeMember')}" title="${I18n.t('form.removeMember')}">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="5" y1="5" x2="15" y2="15"/>
                <line x1="15" y1="5" x2="5" y2="15"/>
              </svg>
            </button>
          ` : ''}
        </div>
        <p class="field-error" id="member-error-${member.id}" hidden aria-live="polite"></p>
      </div>
    `;
    }).join('');

    // Update add button state
    const addBtn = document.getElementById('add-member');
    if (addBtn) {
      addBtn.disabled = this.members.length >= this.MAX_MEMBERS;
    }
  },

  addMember() {
    if (this.members.length >= this.MAX_MEMBERS) return;
    
    const maxId = Math.max(...this.members.map(m => m.id), 0);
    this.members.push({ id: maxId + 1, name: '' });
    this.renderMemberInputs();
  },

  removeMember(id) {
    if (this.members.length <= this.MIN_MEMBERS) return;
    
    this.members = this.members.filter(m => m.id !== id);
    this.renderMemberInputs();
  },

  setFieldError(memberId, message) {
    const input = document.querySelector(`.member-name-input[data-member-id="${memberId}"]`);
    const error = document.getElementById(`member-error-${memberId}`);
    if (!input || !error) return;

    error.textContent = message;
    error.hidden = false;
    input.setAttribute('aria-invalid', 'true');
    input.setAttribute('aria-describedby', error.id);
  },

  clearFieldError(memberId) {
    const input = document.querySelector(`.member-name-input[data-member-id="${memberId}"]`);
    const error = document.getElementById(`member-error-${memberId}`);
    if (!input || !error) return;

    error.textContent = '';
    error.hidden = true;
    input.removeAttribute('aria-invalid');
    input.removeAttribute('aria-describedby');
  },

  clearValidationErrors() {
    this.members.forEach(member => this.clearFieldError(member.id));
  },

  validateMembers() {
    this.clearValidationErrors();

    let firstInvalidId = null;
    const namesCount = new Map();

    this.members.forEach(member => {
      const normalized = member.name.trim().toLowerCase();
      if (normalized) {
        namesCount.set(normalized, (namesCount.get(normalized) || 0) + 1);
      }
    });

    this.members.forEach(member => {
      const normalized = member.name.trim().toLowerCase();

      if (!member.name.trim()) {
        this.setFieldError(member.id, I18n.t('validation.nameRequired'));
        if (!firstInvalidId) firstInvalidId = member.id;
        return;
      }

      if ((namesCount.get(normalized) || 0) > 1) {
        this.setFieldError(member.id, I18n.t('validation.duplicateName'));
        if (!firstInvalidId) firstInvalidId = member.id;
      }
    });

    return firstInvalidId;
  },

  generate() {
    // Collect names from inputs
    this.members.forEach(member => {
      const input = document.querySelector(`.member-name-input[data-member-id="${member.id}"]`);
      if (input) member.name = input.value.trim();
    });

    // Validate
    const firstInvalidId = this.validateMembers();
    if (firstInvalidId) {
      const input = document.querySelector(`.member-name-input[data-member-id="${firstInvalidId}"]`);
      input?.focus();
      this.showToast(I18n.t('toast.fixErrors'), 'error');
      return;
    }

    if (this.members.length < this.MIN_MEMBERS) {
      this.showToast(I18n.t('toast.minMembers'), 'error');
      return;
    }

    this.currentSecret = TOTP.generateSecret();
    
    this.showResults();
    this.updateResults();
    this.startDemo();
    this.showToast(I18n.t('toast.generated'), 'success');
    
    // Update button text
    const btn = document.querySelector('#generate-form button[type="submit"]');
    const span = btn?.querySelector('[data-i18n]');
    if (span) {
      span.setAttribute('data-i18n', 'form.regenerateBtn');
      span.textContent = I18n.t('form.regenerateBtn');
    }
  },

  showResults() {
    const resultsSection = document.getElementById('results');
    if (!resultsSection) return;
    resultsSection.hidden = false;
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  },

  updateResults() {
    const issuer = I18n.t('app.title');
    const qrGrid = document.getElementById('qr-grid');
    
    if (!this.currentSecret || !qrGrid) return;

    const safeIssuer = this.escapeHtml(issuer);

    // Generate QR cards dynamically
    qrGrid.innerHTML = this.members.map((member) => {
      const safeName = this.escapeHtml(member.name);
      return `
      <article class="qr-card" id="qr-card-${member.id}">
        <h3 id="qr-label-${member.id}">${I18n.t('result.qrFor')} ${safeName}</h3>
        <div class="qr-container" id="qr-${member.id}" role="img" aria-labelledby="qr-label-${member.id}"></div>
        <button type="button" class="btn btn-secondary btn-small toggle-manual" aria-expanded="false">
          <span data-i18n="result.manualEntry">${I18n.t('result.manualEntry')}</span>
        </button>
        <div class="manual-details" hidden>
          <p class="manual-instructions">${I18n.t('result.manualInstructions')}</p>
          <div class="manual-field">
            <label>${I18n.t('result.secretLabel')}</label>
            <div class="secret-row">
              <div class="value" id="secret-${member.id}">${TOTP.formatSecret(this.currentSecret)}</div>
              <button type="button" class="btn btn-secondary btn-small" data-copy="${this.currentSecret}">
                ${I18n.t('result.copyBtn')}
              </button>
            </div>
          </div>
          <div class="manual-field">
            <label>${I18n.t('result.issuerLabel')}</label>
            <div class="value">${safeIssuer}</div>
          </div>
          <div class="manual-field">
            <label>${I18n.t('result.accountLabel')}</label>
            <div class="value">${safeName}</div>
          </div>
        </div>
      </article>
    `;
    }).join('');

    // Generate QR codes
    this.members.forEach(member => {
      const uri = TOTP.buildURI({
        secret: this.currentSecret,
        issuer,
        account: member.name
      });

      const qrContainer = document.getElementById(`qr-${member.id}`);
      if (qrContainer && typeof qrcode !== 'undefined') {
        const qr = qrcode(0, 'M');
        qr.addData(uri);
        qr.make();
        
        const img = document.createElement('img');
        img.src = qr.createDataURL(4, 0);
        img.width = 200;
        img.height = 200;
        img.alt = `QR Code for ${member.name}`;
        qrContainer.appendChild(img);
      }
    });

    // Show security warnings
    document.getElementById('security-warnings').hidden = false;
  },

  startDemo() {
    // Stop any existing interval
    if (this.demoInterval) {
      clearInterval(this.demoInterval);
    }

    const demoSection = document.getElementById('demo-section');
    demoSection.hidden = false;

    const updateDemo = async () => {
      const codeEl = document.getElementById('demo-code');
      const timerEl = document.getElementById('demo-timer');
      const progressEl = document.getElementById('demo-progress');
      
      if (!codeEl || !this.currentSecret) return;

      try {
        const code = await TOTP.generateCode(this.currentSecret);
        const remaining = TOTP.getRemainingSeconds();
        
        codeEl.textContent = code.match(/.{1,3}/g)?.join(' ') || code;
        timerEl.textContent = remaining;
        
        // Update progress bar
        if (progressEl) {
          progressEl.style.width = `${(remaining / 30) * 100}%`;
          progressEl.classList.toggle('warning', remaining <= 5);
        }
      } catch (e) {
        console.error('Demo update failed:', e);
      }
    };

    // Update immediately and every second
    updateDemo();
    this.demoInterval = setInterval(updateDemo, 1000);
  },

  async copyToClipboard(button) {
    const text = button.getAttribute('data-copy');
    try {
      await navigator.clipboard.writeText(text);
      const originalText = button.textContent;
      button.textContent = I18n.t('result.copied');
      button.classList.add('copied');
      this.showToast(I18n.t('toast.copied'), 'success');
      setTimeout(() => {
        button.textContent = originalText;
        button.classList.remove('copied');
      }, 2000);
    } catch (err) {
      console.error('Copy failed:', err);
      this.showToast(I18n.t('toast.error'), 'error');
    }
  },

  showToast(message, type = 'info') {
    // Remove existing toast
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'polite');
    toast.textContent = message;

    document.body.appendChild(toast);

    // Trigger animation
    requestAnimationFrame(() => {
      toast.classList.add('show');
    });

    // Remove after delay
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }
};

// Init on DOM ready
document.addEventListener('DOMContentLoaded', () => App.init());
