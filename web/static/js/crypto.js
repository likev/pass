/**
 * Web Password & Key Manager - WebCrypto & Zero-Knowledge Client Cryptography
 */

export const CryptoUtils = {
  // Constant-time buffer comparison to prevent timing attacks on typed confirmation
  constantTimeCompare(a, b) {
    if (a.byteLength !== b.byteLength) return false;
    let diff = 0;
    for (let i = 0; i < a.byteLength; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  },

  // Securely wipe Uint8Array memory
  zeroBuffer(buf) {
    if (buf && buf.fill) {
      buf.fill(0);
    }
  },

  bytesToBase64(bytes) {
    let binary = "";
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  },

  bytesToBase64Url(bytes) {
    return this.bytesToBase64(bytes)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  },

  base64ToBytes(b64) {
    let standard = b64.replace(/-/g, "+").replace(/_/g, "/");
    while (standard.length % 4) {
      standard += "=";
    }
    const binary = atob(standard);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  },

  bytesToHex(bytes) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  },

  async sha256Hex(str) {
    const data = new TextEncoder().encode(str);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return this.bytesToHex(new Uint8Array(hash));
  },

  // Derive Passkey-KEK from WebAuthn PRF output (32 bytes) via HKDF-SHA256
  async derivePasskeyKek(prfOutputBytes, prfSaltBytes) {
    const prfKey = await crypto.subtle.importKey(
      "raw",
      prfOutputBytes,
      "HKDF",
      false,
      ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: prfSaltBytes,
        info: new TextEncoder().encode("passkey-kek-v1"),
      },
      prfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  // Wrap User MEK (256-bit random) using Passkey-KEK
  async wrapMek(passkeyKek, rawMekBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        additionalData: new TextEncoder().encode("user-mek-wrap-v1"),
      },
      passkeyKek,
      rawMekBytes
    );
    return {
      wrappedMek: new Uint8Array(ciphertext),
      wrappedMekIv: iv,
    };
  },

  // Unwrap User MEK using Passkey-KEK
  async unwrapMek(passkeyKek, wrappedMekBytes, ivBytes) {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivBytes,
        additionalData: new TextEncoder().encode("user-mek-wrap-v1"),
      },
      passkeyKek,
      wrappedMekBytes
    );
    return new Uint8Array(decrypted);
  },

  // Derive per-key Client-DEK from MEK + clientSalt + keyName
  async deriveClientKeyDek(rawMekBytes, clientSaltBytes, keyNameNormalized) {
    const mekBaseKey = await crypto.subtle.importKey(
      "raw",
      rawMekBytes,
      "HKDF",
      false,
      ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: clientSaltBytes,
        info: new TextEncoder().encode(keyNameNormalized),
      },
      mekBaseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  // Encrypt plaintext secret in browser memory
  async encryptClientKey(rawMekBytes, keyNameNormalized, plaintextBytes) {
    const clientSalt = crypto.getRandomValues(new Uint8Array(32));
    const clientIv = crypto.getRandomValues(new Uint8Array(12));

    const clientDek = await this.deriveClientKeyDek(
      rawMekBytes,
      clientSalt,
      keyNameNormalized
    );

    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: clientIv,
        additionalData: new TextEncoder().encode(keyNameNormalized),
      },
      clientDek,
      plaintextBytes
    );

    return {
      clientCiphertext: new Uint8Array(ciphertext),
      clientIv,
      clientSalt,
    };
  },

  // Decrypt client ciphertext in memory
  async decryptClientKey(
    rawMekBytes,
    keyNameNormalized,
    clientCiphertextBytes,
    clientIvBytes,
    clientSaltBytes
  ) {
    const clientDek = await this.deriveClientKeyDek(
      rawMekBytes,
      clientSaltBytes,
      keyNameNormalized
    );

    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: clientIvBytes,
        additionalData: new TextEncoder().encode(keyNameNormalized),
      },
      clientDek,
      clientCiphertextBytes
    );

    return new Uint8Array(decrypted);
  },

  // Ephemeral ECDH (P-256) Key Exchange for Verified Device Enrollment
  async generateECDHKeyPair() {
    return crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits", "deriveKey"]
    );
  },

  async exportECDHPublicKey(publicKey) {
    const raw = await crypto.subtle.exportKey("raw", publicKey);
    return new Uint8Array(raw);
  },

  async importECDHPublicKey(rawBytes) {
    return crypto.subtle.importKey(
      "raw",
      rawBytes,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
  },

  // Derive transfer shared key: HKDF-SHA256(ECDH(priv, pub), salt: 6-digit-code, info: "mek-transfer")
  async deriveTransferSharedKey(privateKey, peerPublicKey, pairingCode) {
    const sharedBits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: peerPublicKey },
      privateKey,
      256
    );

    const hkdfKey = await crypto.subtle.importKey(
      "raw",
      sharedBits,
      "HKDF",
      false,
      ["deriveKey"]
    );

    const salt = new TextEncoder().encode(pairingCode);
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: salt,
        info: new TextEncoder().encode("mek-transfer-v1"),
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  async encryptMekTransfer(sharedKey, rawMekBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        additionalData: new TextEncoder().encode("mek-transfer-payload"),
      },
      sharedKey,
      rawMekBytes
    );
    return {
      encryptedMek: new Uint8Array(ciphertext),
      transferIv: iv,
    };
  },

  async decryptMekTransfer(sharedKey, encryptedMekBytes, ivBytes) {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivBytes,
        additionalData: new TextEncoder().encode("mek-transfer-payload"),
      },
      sharedKey,
      encryptedMekBytes
    );
    return new Uint8Array(decrypted);
  },

  // CSPRNG key generator with rejection sampling to eliminate modulo bias
  // Generates unbiased random bytes directly into Uint8Array without DOM or string conversion
  generateSecureKey(mode = "password", length = 32) {
    if (length < 16) length = 16;
    if (length > 128) length = 128;

    const result = new Uint8Array(length);

    if (mode === "hex") {
      // 16 chars; 256 is an exact multiple of 16 -> zero modulo bias
      const hexChars = "0123456789abcdef";
      const randomBytes = crypto.getRandomValues(new Uint8Array(length));
      for (let i = 0; i < length; i++) {
        result[i] = hexChars.charCodeAt(randomBytes[i] % 16);
      }
      this.zeroBuffer(randomBytes);
      return result;
    }

    if (mode === "base64url") {
      // 64 chars; 256 is an exact multiple of 64 -> zero modulo bias
      const b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      const randomBytes = crypto.getRandomValues(new Uint8Array(length));
      for (let i = 0; i < length; i++) {
        result[i] = b64Chars.charCodeAt(randomBytes[i] % 64);
      }
      this.zeroBuffer(randomBytes);
      return result;
    }

    // Default: High-entropy password charset (84 characters)
    const charset =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
    const charsetLen = charset.length;
    // Rejection threshold: max multiple of charsetLen <= 256
    const limit = 256 - (256 % charsetLen);

    let generated = 0;
    const randomChunk = new Uint8Array(length * 2);

    while (generated < length) {
      crypto.getRandomValues(randomChunk);
      for (let i = 0; i < randomChunk.length && generated < length; i++) {
        const val = randomChunk[i];
        if (val < limit) {
          result[generated] = charset.charCodeAt(val % charsetLen);
          generated++;
        }
      }
    }
    this.zeroBuffer(randomChunk);

    return result;
  },
};
