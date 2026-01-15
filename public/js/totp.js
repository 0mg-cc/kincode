/**
 * TOTP secret generation, URI building, and code generation
 * RFC 6238 compliant
 */

const TOTP = {
  /**
   * Generate a cryptographically secure random secret
   * @param {number} length - Number of bytes (default 20 = 160 bits, standard)
   * @returns {Uint8Array}
   */
  generateSecretBytes(length = 20) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  },

  /**
   * Encode bytes to Base32 (RFC 4648)
   * @param {Uint8Array} bytes
   * @returns {string}
   */
  bytesToBase32(bytes) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    let base32 = '';
    
    for (const byte of bytes) {
      bits += byte.toString(2).padStart(8, '0');
    }
    
    // Pad to multiple of 5
    while (bits.length % 5 !== 0) {
      bits += '0';
    }
    
    for (let i = 0; i < bits.length; i += 5) {
      const chunk = bits.slice(i, i + 5);
      base32 += alphabet[parseInt(chunk, 2)];
    }
    
    return base32;
  },

  /**
   * Decode Base32 to bytes
   * @param {string} base32
   * @returns {Uint8Array}
   */
  base32ToBytes(base32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    
    for (const char of base32.toUpperCase().replace(/\s/g, '')) {
      const idx = alphabet.indexOf(char);
      if (idx === -1) continue;
      bits += idx.toString(2).padStart(5, '0');
    }
    
    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(bits.slice(i * 8, (i + 1) * 8), 2);
    }
    
    return bytes;
  },

  /**
   * Generate a new Base32 secret
   * @returns {string}
   */
  generateSecret() {
    const bytes = this.generateSecretBytes(20);
    return this.bytesToBase32(bytes);
  },

  /**
   * Build otpauth:// URI for TOTP
   * @param {Object} params
   * @param {string} params.secret - Base32 encoded secret
   * @param {string} params.issuer - Issuer name
   * @param {string} params.account - Account name
   * @param {number} [params.digits=6] - Number of digits
   * @param {number} [params.period=30] - Time period in seconds
   * @param {string} [params.algorithm='SHA1'] - Hash algorithm
   * @returns {string}
   */
  buildURI({ secret, issuer, account, digits = 6, period = 30, algorithm = 'SHA1' }) {
    const encodedIssuer = encodeURIComponent(issuer);
    const encodedAccount = encodeURIComponent(account);
    const label = issuer ? `${encodedIssuer}:${encodedAccount}` : encodedAccount;
    
    const params = new URLSearchParams({
      secret,
      issuer,
      algorithm,
      digits: digits.toString(),
      period: period.toString()
    });
    
    return `otpauth://totp/${label}?${params.toString()}`;
  },

  /**
   * Format secret for display (groups of 4)
   * @param {string} secret
   * @returns {string}
   */
  formatSecret(secret) {
    return secret.match(/.{1,4}/g)?.join(' ') || secret;
  },

  /**
   * Generate TOTP code from secret
   * Uses Web Crypto API for HMAC-SHA1
   * @param {string} secret - Base32 encoded secret
   * @param {number} [time] - Unix timestamp (defaults to now)
   * @param {number} [period=30] - Time period in seconds
   * @param {number} [digits=6] - Number of digits
   * @returns {Promise<string>}
   */
  async generateCode(secret, time = Date.now(), period = 30, digits = 6) {
    const counter = Math.floor(time / 1000 / period);
    const secretBytes = this.base32ToBytes(secret);
    
    // Convert counter to 8-byte big-endian buffer
    const counterBuffer = new ArrayBuffer(8);
    const counterView = new DataView(counterBuffer);
    counterView.setUint32(4, counter, false); // Big-endian, lower 32 bits
    
    // Import key for HMAC
    const key = await crypto.subtle.importKey(
      'raw',
      secretBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );
    
    // Generate HMAC
    const signature = await crypto.subtle.sign('HMAC', key, counterBuffer);
    const hmac = new Uint8Array(signature);
    
    // Dynamic truncation (RFC 4226)
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary = 
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);
    
    const otp = binary % Math.pow(10, digits);
    return otp.toString().padStart(digits, '0');
  },

  /**
   * Get remaining seconds in current period
   * @param {number} [period=30]
   * @returns {number}
   */
  getRemainingSeconds(period = 30) {
    return period - (Math.floor(Date.now() / 1000) % period);
  }
};

export default TOTP;
