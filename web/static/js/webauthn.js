/**
 * Web Password & Key Manager - WebAuthn & PRF Extension Client Library
 */

import { CryptoUtils } from "./crypto.js";

export const WebAuthnHelper = {
  // Decode base64url string to ArrayBuffer for WebAuthn APIs
  base64ToArrayBuffer(base64Url) {
    const bytes = CryptoUtils.base64ToBytes(base64Url);
    return bytes.buffer;
  },

  // Encode ArrayBuffer to base64url string
  arrayBufferToBase64(buffer) {
    return CryptoUtils.bytesToBase64Url(new Uint8Array(buffer));
  },

  // Parse server PublicKeyCredentialCreationOptions and inject PRF extension
  prepareCreationOptions(serverOptions, prfSaltBytes) {
    const options = { ...serverOptions };

    if (options.challenge) {
      options.challenge = this.base64ToArrayBuffer(options.challenge);
    }
    if (options.user && options.user.id) {
      options.user.id = this.base64ToArrayBuffer(options.user.id);
    }
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map((c) => ({
        ...c,
        id: this.base64ToArrayBuffer(c.id),
      }));
    }

    // Attach PRF extension request
    if (prfSaltBytes) {
      options.extensions = {
        ...(options.extensions || {}),
        prf: {
          eval: {
            first: prfSaltBytes.buffer || prfSaltBytes,
          },
        },
      };
    }

    return options;
  },

  // Serialize navigator.credentials.create response
  serializeCreationResponse(credential) {
    const response = credential.response;
    const transports = response.getTransports ? response.getTransports() : [];

    return {
      id: credential.id,
      rawId: this.arrayBufferToBase64(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: this.arrayBufferToBase64(response.clientDataJSON),
        attestationObject: this.arrayBufferToBase64(response.attestationObject),
        transports: transports,
      },
      clientExtensionResults: credential.getClientExtensionResults(),
    };
  },

  // Parse server PublicKeyCredentialRequestOptions and inject PRF extension
  prepareRequestOptions(serverOptions, prfSaltBytes) {
    const options = { ...serverOptions };

    if (options.challenge) {
      options.challenge = this.base64ToArrayBuffer(options.challenge);
    }
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((c) => ({
        ...c,
        id: this.base64ToArrayBuffer(c.id),
      }));
    }

    if (prfSaltBytes) {
      options.extensions = {
        ...(options.extensions || {}),
        prf: {
          eval: {
            first: prfSaltBytes.buffer || prfSaltBytes,
          },
        },
      };
    }

    return options;
  },

  // Serialize navigator.credentials.get response
  serializeAssertionResponse(assertion) {
    const response = assertion.response;

    return {
      id: assertion.id,
      rawId: this.arrayBufferToBase64(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: this.arrayBufferToBase64(response.clientDataJSON),
        authenticatorData: this.arrayBufferToBase64(response.authenticatorData),
        signature: this.arrayBufferToBase64(response.signature),
        userHandle: response.userHandle
          ? this.arrayBufferToBase64(response.userHandle)
          : null,
      },
      clientExtensionResults: assertion.getClientExtensionResults(),
    };
  },

  // Extract PRF extension result bytes
  extractPRFOutput(credential) {
    const extResults = credential.getClientExtensionResults();
    if (extResults && extResults.prf && extResults.prf.results && extResults.prf.results.first) {
      return new Uint8Array(extResults.prf.results.first);
    }
    return null;
  },
};
