/**
 * Web Password & Key Manager - Main Application Logic
 */

import { CryptoUtils } from "./crypto.js";
import { WebAuthnHelper } from "./webauthn.js";
import { ClipboardGuard } from "./clipboard.js";

// Application State
const state = {
  csrfToken: null,
  currentUser: null,
  activeCredId: null,
  sealed: true,
  initialized: false,
  pendingPastedBytes: null, // Ephemeral Uint8Array for pasted key
  pendingNewPhoneECDH: null,
  pendingNewPhoneCode: null,
  pendingNewPhoneRequestId: null,
  phonePollTimer: null,
};

// UI Elements
const els = {
  bannerClipboard: document.getElementById("banner-clipboard"),
  clipboardText: document.getElementById("clipboard-text"),
  clipboardProgressBar: document.getElementById("clipboard-progress-bar"),
  btnClearClipboard: document.getElementById("btn-clear-clipboard"),

  viewUnseal: document.getElementById("view-unseal"),
  viewAuth: document.getElementById("view-auth"),
  viewDashboard: document.getElementById("view-dashboard"),

  // Unseal
  unsealTitle: document.getElementById("unseal-title"),
  unsealDesc: document.getElementById("unseal-desc"),
  unsealPass: document.getElementById("unseal-passphrase"),
  unsealPassConfirmRow: document.getElementById("unseal-passphrase-confirm-row"),
  unsealPassConfirm: document.getElementById("unseal-passphrase-confirm"),
  btnUnsealSubmit: document.getElementById("btn-unseal-submit"),
  unsealAlert: document.getElementById("unseal-alert"),

  // Auth
  authAlert: document.getElementById("auth-alert"),
  regUsername: document.getElementById("reg-username"),
  regDisplayName: document.getElementById("reg-display-name"),
  regDeviceName: document.getElementById("reg-device-name"),
  btnRegister: document.getElementById("btn-register"),
  loginUsername: document.getElementById("login-username"),
  btnLogin: document.getElementById("btn-login"),

  // Dashboard
  userDisplayName: document.getElementById("user-display-name"),
  btnLogout: document.getElementById("btn-logout"),
  keysFilter: document.getElementById("keys-filter"),
  keysList: document.getElementById("keys-list"),
  keysAlert: document.getElementById("keys-alert"),

  // Create Key Modal & Form
  btnOpenCreateKey: document.getElementById("btn-open-create-key"),
  modalCreateKey: document.getElementById("modal-create-key"),
  btnCloseCreateKey: document.getElementById("btn-close-create-key"),
  keyName: document.getElementById("key-name"),
  tabType: document.getElementById("tab-type"),
  tabPaste: document.getElementById("tab-paste"),
  tabGen: document.getElementById("tab-gen"),
  sectionType: document.getElementById("section-type"),
  sectionPaste: document.getElementById("section-paste"),
  sectionGen: document.getElementById("section-gen"),
  keyTypePrimary: document.getElementById("key-type-primary"),
  keyTypeConfirm: document.getElementById("key-type-confirm"),
  pasteStatusBadge: document.getElementById("paste-status-badge"),
  btnPasteCapture: document.getElementById("btn-paste-capture"),
  genPreset: document.getElementById("gen-preset"),
  genLength: document.getElementById("gen-length"),
  genLengthVal: document.getElementById("gen-length-val"),
  genCopyCheckbox: document.getElementById("gen-copy-checkbox"),
  btnSaveKey: document.getElementById("btn-save-key"),
  createKeyAlert: document.getElementById("create-key-alert"),

  // Devices View
  btnOpenDevices: document.getElementById("btn-open-devices"),
  modalDevices: document.getElementById("modal-devices"),
  btnCloseDevices: document.getElementById("btn-close-devices"),
  devicesList: document.getElementById("devices-list"),
  pendingRequestsList: document.getElementById("pending-requests-list"),
  btnAddPhone: document.getElementById("btn-add-phone"),
  btnChangePhone: document.getElementById("btn-change-phone"),
  newPhoneSection: document.getElementById("new-phone-section"),
  newPhoneCodeDisplay: document.getElementById("new-phone-code-display"),
  newPhoneStatusText: document.getElementById("new-phone-status-text"),
  devicesAlert: document.getElementById("devices-alert"),
};

// Initialize Clipboard Guard
ClipboardGuard.init(
  (remainingMs, reason, pendingClear) => {
    if (pendingClear) {
      els.bannerClipboard.style.display = "flex";
      els.clipboardText.textContent = "⚠️ Background clipboard wipe pending — focus tab or click to clear!";
      els.clipboardProgressBar.style.width = "100%";
      return;
    }
    if (remainingMs <= 0) {
      els.bannerClipboard.style.display = "none";
      return;
    }
    els.bannerClipboard.style.display = "flex";
    const totalSec = Math.ceil(remainingMs / 1000);
    const mins = Math.floor(totalSec / 60);
    const secs = totalSec % 60;
    const timeStr = `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
    const actionLabel = reason === "pasted" ? "Pasted secret in clipboard" : "Decrypted key in clipboard";
    els.clipboardText.textContent = `${actionLabel} — auto-clearing in ${timeStr}`;
    const percent = ((180000 - remainingMs) / 180000) * 100;
    els.clipboardProgressBar.style.width = `${percent}%`;
  },
  () => {
    els.bannerClipboard.style.display = "none";
    showAlert(els.keysAlert, "Clipboard securely auto-cleared.", "info");
  }
);

els.btnClearClipboard.addEventListener("click", async () => {
  await ClipboardGuard.clearNow();
  els.bannerClipboard.style.display = "none";
});

// Helper for Fetch API with CSRF token
async function apiFetch(url, options = {}) {
  options.headers = options.headers || {};
  options.headers["Cache-Control"] = "no-store";
  if (state.csrfToken && options.method && options.method !== "GET") {
    options.headers["X-CSRF-Token"] = state.csrfToken;
  }
  const res = await fetch(url, options);
  return res;
}

function showAlert(el, msg, type = "error") {
  if (!el) return;
  el.textContent = msg;
  el.className = `alert alert-${type}`;
  el.style.display = "block";
  if (type === "info" || type === "success") {
    setTimeout(() => {
      if (el.textContent === msg) {
        el.style.display = "none";
      }
    }, 4000);
  }
}

function hideAlert(el) {
  if (el) el.style.display = "none";
}

// Consistent PRF evaluation helper across create() and get()
async function getOrDerivePasskeyKek(credential, prfSaltBytes, isCreation = false) {
  let prfOutput = WebAuthnHelper.extractPRFOutput(credential);
  if (!prfOutput && isCreation && credential.rawId) {
    // If authenticator enabled PRF during create, evaluate it via immediate assertion
    try {
      const extResults = credential.getClientExtensionResults ? credential.getClientExtensionResults() : {};
      if (extResults && extResults.prf && extResults.prf.enabled) {
        const assertion = await navigator.credentials.get({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials: [{ id: credential.rawId, type: "public-key" }],
            userVerification: "preferred",
            timeout: 60000,
          },
          extensions: {
            prf: {
              eval: {
                first: prfSaltBytes.buffer || prfSaltBytes,
              },
            },
          },
        });
        if (assertion) {
          prfOutput = WebAuthnHelper.extractPRFOutput(assertion);
        }
      }
    } catch (e) {
      console.warn("Could not evaluate PRF on creation:", e);
    }
  }

  if (prfOutput) {
    const kek = await CryptoUtils.derivePasskeyKek(prfOutput, prfSaltBytes);
    CryptoUtils.zeroBuffer(prfOutput);
    return kek;
  }

  // Consistent fallback for authenticators lacking PRF hardware extension
  return CryptoUtils.derivePasskeyKek(new Uint8Array(credential.rawId), prfSaltBytes);
}

// Check Server Seal Status
async function checkSealStatus() {
  try {
    const res = await fetch("/api/v1/admin/seal-status", { cache: "no-store" });
    const data = await res.json();
    state.initialized = data.initialized;
    state.sealed = !data.unsealed;

    if (state.sealed) {
      showView("unseal");
      if (!state.initialized) {
        els.unsealTitle.textContent = "First-Time Server Initialization";
        els.unsealDesc.textContent =
          "Please set a strong Admin Startup Passphrase (min 12 chars). This will seal the Server Master Key (SMK) via Argon2id + AES-256-GCM.";
        els.unsealPassConfirmRow.style.display = "block";
        els.btnUnsealSubmit.textContent = "Initialize & Unseal Server";
      } else {
        els.unsealTitle.textContent = "Server Sealed";
        els.unsealDesc.textContent =
          "Enter your Admin Startup Passphrase to unseal the Server Master Key into RAM.";
        els.unsealPassConfirmRow.style.display = "none";
        els.btnUnsealSubmit.textContent = "Unseal Server";
      }
    } else {
      await checkAuthStatus();
    }
  } catch (err) {
    showView("unseal");
    showAlert(els.unsealAlert, "Failed to connect to backend server: " + err.message);
  }
}

// Unseal Form Submission
els.btnUnsealSubmit.addEventListener("click", async () => {
  hideAlert(els.unsealAlert);
  const pass = els.unsealPass.value;
  if (pass.length < 12) {
    showAlert(els.unsealAlert, "Passphrase must be at least 12 characters.");
    return;
  }

  const payload = { passphrase: pass };
  if (!state.initialized) {
    const confirm = els.unsealPassConfirm.value;
    if (pass !== confirm) {
      showAlert(els.unsealAlert, "Passphrases do not match.");
      return;
    }
    payload.confirm_passphrase = confirm;
  }

  try {
    const res = await fetch("/api/v1/admin/unseal", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      showAlert(els.unsealAlert, data.message || data.error || "Unseal failed");
      return;
    }

    // Wipe DOM input values
    els.unsealPass.value = "";
    els.unsealPassConfirm.value = "";
    state.sealed = false;
    await checkAuthStatus();
  } catch (err) {
    showAlert(els.unsealAlert, err.message);
  }
});

// Check Authentication Status
async function checkAuthStatus() {
  try {
    const res = await apiFetch("/api/v1/auth/me");
    if (res.ok) {
      const data = await res.json();
      state.currentUser = data.user;
      state.activeCredId = data.credential_id;
      state.csrfToken = data.csrf_token;
      showView("dashboard");
      els.userDisplayName.textContent = data.user.display_name || data.user.username;
      loadKeys();
    } else {
      showView("auth");
    }
  } catch (err) {
    showView("auth");
  }
}

function showView(view) {
  els.viewUnseal.style.display = view === "unseal" ? "block" : "none";
  els.viewAuth.style.display = view === "auth" ? "block" : "none";
  els.viewDashboard.style.display = view === "dashboard" ? "block" : "none";
}

// ===================== Passkey Registration & Login =====================

els.btnRegister.addEventListener("click", async () => {
  hideAlert(els.authAlert);
  const username = els.regUsername.value.trim();
  const displayName = els.regDisplayName.value.trim() || username;
  const deviceName = els.regDeviceName.value.trim() || "My Device";

  if (!username) {
    showAlert(els.authAlert, "Username is required for registration.");
    return;
  }

  try {
    // 1. Begin registration
    const beginRes = await fetch("/api/v1/auth/register/begin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, display_name: displayName }),
    });
    const beginData = await beginRes.json();
    if (!beginRes.ok) throw new Error(beginData.message || beginData.error);

    const prfSaltBytes = CryptoUtils.base64ToBytes(beginData.prf_salt);
    const creationOptions = WebAuthnHelper.prepareCreationOptions(
      beginData.options.publicKey,
      prfSaltBytes
    );

    // 2. Call WebAuthn API with PRF extension
    const credential = await navigator.credentials.create({
      publicKey: creationOptions,
    });

    // 3. Derive Passkey-KEK from PRF output & Generate initial User MEK
    const passkeyKek = await getOrDerivePasskeyKek(credential, prfSaltBytes, true);

    const rawMek = crypto.getRandomValues(new Uint8Array(32));
    const { wrappedMek, wrappedMekIv } = await CryptoUtils.wrapMek(passkeyKek, rawMek);
    CryptoUtils.zeroBuffer(rawMek);

    // 4. Finish registration
    const finishRes = await fetch("/api/v1/auth/register/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        reg_id: beginData.reg_id,
        attestation: WebAuthnHelper.serializeCreationResponse(credential),
        wrapped_mek: CryptoUtils.bytesToBase64Url(wrappedMek),
        wrapped_mek_iv: CryptoUtils.bytesToBase64Url(wrappedMekIv),
        device_name: deviceName,
      }),
    });
    const finishData = await finishRes.json();
    if (!finishRes.ok) throw new Error(finishData.message || finishData.error);

    state.csrfToken = finishData.csrf_token;
    state.currentUser = finishData.user;
    showView("dashboard");
    els.userDisplayName.textContent = finishData.user.display_name;
    loadKeys();
  } catch (err) {
    showAlert(els.authAlert, "Registration failed: " + err.message);
  }
});

els.btnLogin.addEventListener("click", async () => {
  hideAlert(els.authAlert);
  const username = els.loginUsername.value.trim();

  try {
    const beginRes = await fetch("/api/v1/auth/login/begin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });
    const beginData = await beginRes.json();
    if (!beginRes.ok) throw new Error(beginData.message || beginData.error);

    let prfSaltBytes = null;
    if (beginData.prf_salts && beginData.prf_salts.length > 0) {
      prfSaltBytes = CryptoUtils.base64ToBytes(beginData.prf_salts[0]);
    }

    const requestOptions = WebAuthnHelper.prepareRequestOptions(
      beginData.options.publicKey,
      prfSaltBytes
    );

    const assertion = await navigator.credentials.get({
      publicKey: requestOptions,
    });

    const finishRes = await fetch("/api/v1/auth/login/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        login_id: beginData.login_id,
        assertion: WebAuthnHelper.serializeAssertionResponse(assertion),
      }),
    });
    const finishData = await finishRes.json();
    if (!finishRes.ok) throw new Error(finishData.message || finishData.error);

    state.csrfToken = finishData.csrf_token;
    state.currentUser = finishData.user;
    showView("dashboard");
    els.userDisplayName.textContent = finishData.user.display_name;
    loadKeys();
  } catch (err) {
    showAlert(els.authAlert, "Login failed: " + err.message);
  }
});

els.btnLogout.addEventListener("click", async () => {
  await apiFetch("/api/v1/auth/logout", { method: "POST" });
  await ClipboardGuard.clearNow();
  state.currentUser = null;
  state.csrfToken = null;
  showView("auth");
});

// ===================== Keys Management & Single-Key Fetch =====================

let searchDebounce = null;
els.keysFilter.addEventListener("input", () => {
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(() => {
    loadKeys(els.keysFilter.value);
  }, 250);
});

async function loadKeys(query = "") {
  try {
    const res = await apiFetch(`/api/v1/keys?q=${encodeURIComponent(query)}`);
    if (!res.ok) return;
    const data = await res.json();
    renderKeys(data.keys || []);
  } catch (err) {
    showAlert(els.keysAlert, "Failed to load keys: " + err.message);
  }
}

function renderKeys(keys) {
  els.keysList.innerHTML = "";
  if (keys.length === 0) {
    els.keysList.innerHTML = `<li class="empty-list">No keys found. Click "+ Create New Key" to store your first key.</li>`;
    return;
  }

  for (const k of keys) {
    const li = document.createElement("li");
    li.className = "key-item";

    const info = document.createElement("div");
    info.className = "key-info";

    const name = document.createElement("span");
    name.className = "key-title";
    name.textContent = k.name;

    const date = document.createElement("span");
    date.className = "key-date";
    date.textContent = `Updated: ${new Date(k.updated_at).toLocaleString()}`;

    info.appendChild(name);
    info.appendChild(date);

    const actions = document.createElement("div");
    actions.className = "key-actions";

    const btnCopy = document.createElement("button");
    btnCopy.className = "btn btn-primary btn-sm";
    btnCopy.textContent = "Copy Key";
    btnCopy.addEventListener("click", () => copySingleKey(k.id, k.name));

    const btnDelete = document.createElement("button");
    btnDelete.className = "btn btn-danger btn-sm";
    btnDelete.textContent = "Delete";
    btnDelete.addEventListener("click", () => deleteKey(k.id, k.name));

    actions.appendChild(btnCopy);
    actions.appendChild(btnDelete);

    li.appendChild(info);
    li.appendChild(actions);
    els.keysList.appendChild(li);
  }
}

// Single-Key Retrieval & Direct Clipboard Decryption
// Uses writeViaPromise so browser preserves transient user activation across WebAuthn + retrieve fetch
async function copySingleKey(keyId, keyName) {
  hideAlert(els.keysAlert);
  try {
    const keyBlobPromise = (async () => {
      // 1. Step-up Challenge
      const chRes = await apiFetch(`/api/v1/keys/${encodeURIComponent(keyId)}/challenge`, {
        method: "POST",
      });
      const chData = await chRes.json();
      if (!chRes.ok) throw new Error(chData.message || chData.error);

      const prfSaltBytes = CryptoUtils.base64ToBytes(chData.prf_salt);
      const reqOptions = WebAuthnHelper.prepareRequestOptions(
        chData.options.publicKey,
        prfSaltBytes
      );

      // 2. Passkey Assertion + PRF
      const assertion = await navigator.credentials.get({ publicKey: reqOptions });

      // 3. Fetch Single Key Ciphertext
      const retRes = await apiFetch(`/api/v1/keys/${encodeURIComponent(keyId)}/retrieve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          step_up_id: chData.step_up_id,
          assertion: WebAuthnHelper.serializeAssertionResponse(assertion),
        }),
      });
      const keyData = await retRes.json();
      if (!retRes.ok) throw new Error(keyData.message || keyData.error);

      // 4. Derive Passkey-KEK & Unwrap MEK
      const passkeyKek = await getOrDerivePasskeyKek(assertion, prfSaltBytes, false);

      const wrappedMekBytes = CryptoUtils.base64ToBytes(keyData.wrapped_mek);
      const wrappedMekIv = CryptoUtils.base64ToBytes(keyData.wrapped_mek_iv);
      const rawMek = await CryptoUtils.unwrapMek(passkeyKek, wrappedMekBytes, wrappedMekIv);

      // 5. Decrypt Client Ciphertext into Transient Uint8Array
      const clientCT = CryptoUtils.base64ToBytes(keyData.client_ciphertext);
      const clientIV = CryptoUtils.base64ToBytes(keyData.client_iv);
      const clientSalt = CryptoUtils.base64ToBytes(keyData.client_salt);
      const keyNameNorm = (keyData.name || keyName).toLowerCase().trim();

      const plaintextBytes = await CryptoUtils.decryptClientKey(
        rawMek,
        keyNameNorm,
        clientCT,
        clientIV,
        clientSalt
      );
      CryptoUtils.zeroBuffer(rawMek);

      try {
        return new Blob([plaintextBytes], { type: "text/plain" });
      } finally {
        CryptoUtils.zeroBuffer(plaintextBytes);
      }
    })();

    await ClipboardGuard.writeViaPromise(keyBlobPromise, "copied");
    showAlert(els.keysAlert, `Key "${keyName}" decrypted directly to clipboard! (Auto-clears in 3 minutes)`, "success");
  } catch (err) {
    showAlert(els.keysAlert, "Failed to retrieve/decrypt key: " + err.message);
  }
}

async function deleteKey(keyId, keyName) {
  if (!confirm(`Are you sure you want to delete "${keyName}"? Passkey verification required.`)) {
    return;
  }
  try {
    const chRes = await apiFetch(`/api/v1/keys/${encodeURIComponent(keyId)}/challenge`, {
      method: "POST",
    });
    const chData = await chRes.json();
    if (!chRes.ok) throw new Error(chData.message || chData.error);

    const reqOptions = WebAuthnHelper.prepareRequestOptions(chData.options.publicKey);
    const assertion = await navigator.credentials.get({ publicKey: reqOptions });

    const delRes = await apiFetch(`/api/v1/keys/${encodeURIComponent(keyId)}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        step_up_id: chData.step_up_id,
        assertion: WebAuthnHelper.serializeAssertionResponse(assertion),
      }),
    });
    if (!delRes.ok) {
      const errData = await delRes.json();
      throw new Error(errData.message || errData.error);
    }
    showAlert(els.keysAlert, `Key "${keyName}" deleted.`, "info");
    loadKeys(els.keysFilter.value);
  } catch (err) {
    showAlert(els.keysAlert, "Delete failed: " + err.message);
  }
}

// ===================== 3-Mode Key Creation =====================

let activeMode = "type"; // "type" | "paste" | "gen"

els.btnOpenCreateKey.addEventListener("click", () => {
  resetCreateKeyModal();
  els.modalCreateKey.style.display = "flex";
});

els.btnCloseCreateKey.addEventListener("click", () => {
  resetCreateKeyModal();
  els.modalCreateKey.style.display = "none";
});

function resetCreateKeyModal() {
  hideAlert(els.createKeyAlert);
  els.keyName.value = "";
  els.keyTypePrimary.value = "";
  els.keyTypeConfirm.value = "";
  if (state.pendingPastedBytes) {
    CryptoUtils.zeroBuffer(state.pendingPastedBytes);
    state.pendingPastedBytes = null;
  }
  els.pasteStatusBadge.textContent = "No pasted key captured yet.";
  els.pasteStatusBadge.className = "badge badge-neutral";
  switchMode("type");
}

function switchMode(mode) {
  activeMode = mode;
  els.tabType.className = mode === "type" ? "tab active" : "tab";
  els.tabPaste.className = mode === "paste" ? "tab active" : "tab";
  els.tabGen.className = mode === "gen" ? "tab active" : "tab";

  els.sectionType.style.display = mode === "type" ? "block" : "none";
  els.sectionPaste.style.display = mode === "paste" ? "block" : "none";
  els.sectionGen.style.display = mode === "gen" ? "block" : "none";
}

els.tabType.addEventListener("click", () => switchMode("type"));
els.tabPaste.addEventListener("click", () => switchMode("paste"));
els.tabGen.addEventListener("click", () => switchMode("gen"));

// Block pasting on Confirm Input so user actually types twice
els.keyTypeConfirm.addEventListener("paste", (e) => {
  e.preventDefault();
  showAlert(els.createKeyAlert, "Pasting into the confirmation field is disabled. Please type to confirm.");
});
els.keyTypeConfirm.addEventListener("drop", (e) => e.preventDefault());

// Intercept paste on keyTypePrimary: switch to paste mode and capture directly into RAM
els.keyTypePrimary.addEventListener("paste", async (e) => {
  e.preventDefault();
  const text = e.clipboardData ? e.clipboardData.getData("text/plain") : "";
  if (text) {
    switchMode("paste");
    await capturePasteDirect(text);
  }
});

// Capture Pasted Key directly into memory & trigger 3-min clipboard auto-clear
async function capturePasteDirect(text) {
  if (!text) return;
  if (state.pendingPastedBytes) {
    CryptoUtils.zeroBuffer(state.pendingPastedBytes);
  }
  state.pendingPastedBytes = new TextEncoder().encode(text);
  els.pasteStatusBadge.textContent = `Pasted secret captured in memory (${state.pendingPastedBytes.length} bytes) — ready to encrypt`;
  els.pasteStatusBadge.className = "badge badge-success";
  // Activate 3-minute clear countdown because user pasted from clipboard
  ClipboardGuard.scheduleClear(180 * 1000, "pasted");
}

els.btnPasteCapture.addEventListener("click", async () => {
  try {
    const text = await navigator.clipboard.readText();
    await capturePasteDirect(text);
  } catch (err) {
    showAlert(els.createKeyAlert, "Clipboard read permission denied. You can press Ctrl+V / Cmd+V in this window instead.");
  }
});

window.addEventListener("paste", async (e) => {
  if (els.modalCreateKey.style.display === "flex" && activeMode === "paste") {
    e.preventDefault();
    const text = e.clipboardData.getData("text/plain");
    await capturePasteDirect(text);
  }
});

els.genLength.addEventListener("input", () => {
  els.genLengthVal.textContent = els.genLength.value;
});

// Submit Create Key
els.btnSaveKey.addEventListener("click", async () => {
  hideAlert(els.createKeyAlert);
  const name = els.keyName.value.trim();
  if (!name) {
    showAlert(els.createKeyAlert, "Please provide a Key Name.");
    return;
  }

  let plaintextBytes = null;
  let genClipboardBytes = null;

  try {
    if (activeMode === "type") {
      const p1 = els.keyTypePrimary.value;
      const p2 = els.keyTypeConfirm.value;
      if (!p1) {
        showAlert(els.createKeyAlert, "Please enter the key.");
        return;
      }

      const buf1 = new TextEncoder().encode(p1);
      const buf2 = new TextEncoder().encode(p2);

      // Immediately clear DOM inputs
      els.keyTypePrimary.value = "";
      els.keyTypeConfirm.value = "";

      const match = CryptoUtils.constantTimeCompare(buf1, buf2);
      CryptoUtils.zeroBuffer(buf2);

      if (!match) {
        CryptoUtils.zeroBuffer(buf1);
        showAlert(els.createKeyAlert, "Key confirmation does not match. Please re-enter.");
        return;
      }
      plaintextBytes = buf1;
    } else if (activeMode === "paste") {
      if (!state.pendingPastedBytes || state.pendingPastedBytes.length === 0) {
        showAlert(els.createKeyAlert, "No pasted key captured. Click 'Paste from Clipboard' first.");
        return;
      }
      plaintextBytes = state.pendingPastedBytes;
      state.pendingPastedBytes = null;
    } else if (activeMode === "gen") {
      const mode = els.genPreset.value;
      const length = parseInt(els.genLength.value, 10);
      plaintextBytes = CryptoUtils.generateSecureKey(mode, length);

      if (els.genCopyCheckbox.checked) {
        // Prepare defensive copy to write to clipboard ONLY after successful save
        genClipboardBytes = new Uint8Array(plaintextBytes.length);
        genClipboardBytes.set(plaintextBytes);
      }
    }

    // Step-up Passkey Prompt to unwrap MEK
    const chRes = await apiFetch(`/api/v1/keys/new/challenge`, { method: "POST" });
    const chData = await chRes.json();
    if (!chRes.ok) throw new Error(chData.message || chData.error);

    const prfSaltBytes = CryptoUtils.base64ToBytes(chData.prf_salt);
    const reqOptions = WebAuthnHelper.prepareRequestOptions(chData.options.publicKey, prfSaltBytes);
    const assertion = await navigator.credentials.get({ publicKey: reqOptions });

    const passkeyKek = await getOrDerivePasskeyKek(assertion, prfSaltBytes, false);

    const wrappedMekBytes = CryptoUtils.base64ToBytes(chData.wrapped_mek);
    const wrappedMekIv = CryptoUtils.base64ToBytes(chData.wrapped_mek_iv);
    const rawMek = await CryptoUtils.unwrapMek(passkeyKek, wrappedMekBytes, wrappedMekIv);

    // Encrypt client-side
    const keyNameNorm = name.toLowerCase();
    const { clientCiphertext, clientIv, clientSalt } = await CryptoUtils.encryptClientKey(
      rawMek,
      keyNameNorm,
      plaintextBytes
    );

    // Zero memory buffers
    CryptoUtils.zeroBuffer(rawMek);
    CryptoUtils.zeroBuffer(plaintextBytes);
    plaintextBytes = null;

    // Send to backend
    const createRes = await apiFetch("/api/v1/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: name,
        client_ciphertext: CryptoUtils.bytesToBase64Url(clientCiphertext),
        client_iv: CryptoUtils.bytesToBase64Url(clientIv),
        client_salt: CryptoUtils.bytesToBase64Url(clientSalt),
      }),
    });
    const createData = await createRes.json();
    if (!createRes.ok) throw new Error(createData.message || createData.error);

    // Write generated key to clipboard AFTER successful database save
    if (genClipboardBytes) {
      await ClipboardGuard.writeBytesDirect(genClipboardBytes, "generated");
      genClipboardBytes = null;
    }

    resetCreateKeyModal();
    els.modalCreateKey.style.display = "none";
    showAlert(els.keysAlert, `Key "${name}" encrypted and saved!`, "success");
    loadKeys();
  } catch (err) {
    if (plaintextBytes) CryptoUtils.zeroBuffer(plaintextBytes);
    if (genClipboardBytes) CryptoUtils.zeroBuffer(genClipboardBytes);
    showAlert(els.createKeyAlert, "Failed to save key: " + err.message);
  }
});

// ===================== Devices & Verified-Device Phone Enrollment =====================

els.btnOpenDevices.addEventListener("click", () => {
  els.modalDevices.style.display = "flex";
  loadDevicesAndRequests();
});

els.btnCloseDevices.addEventListener("click", () => {
  if (state.phonePollTimer) {
    clearInterval(state.phonePollTimer);
    state.phonePollTimer = null;
  }
  els.modalDevices.style.display = "none";
});

async function loadDevicesAndRequests() {
  try {
    const devRes = await apiFetch("/api/v1/devices");
    const devData = await devRes.json();
    renderDevices(devData.devices || []);

    const reqRes = await apiFetch("/api/v1/devices/requests/pending");
    const reqData = await reqRes.json();
    renderPendingRequests(reqData.requests || []);
  } catch (err) {
    showAlert(els.devicesAlert, err.message);
  }
}

// XSS-Safe Device Rendering using textContent and DOM APIs
function renderDevices(devices) {
  els.devicesList.innerHTML = "";
  for (const d of devices) {
    const li = document.createElement("li");
    li.className = "device-item";

    const info = document.createElement("div");
    const nameEl = document.createElement("strong");
    nameEl.textContent = d.device_name;

    const badge = document.createElement("span");
    badge.className = `badge badge-${d.status === "verified" ? "success" : "neutral"}`;
    badge.textContent = d.status;

    const dateEl = document.createElement("small");
    dateEl.className = "text-muted";
    dateEl.textContent = `Enrolled: ${new Date(d.created_at).toLocaleDateString()}`;

    info.appendChild(nameEl);
    info.appendChild(document.createTextNode(" "));
    info.appendChild(badge);
    info.appendChild(document.createElement("br"));
    info.appendChild(dateEl);

    const actions = document.createElement("div");
    if (d.status === "verified" && devices.filter((x) => x.status === "verified").length > 1) {
      const btnRevoke = document.createElement("button");
      btnRevoke.className = "btn btn-danger btn-sm";
      btnRevoke.textContent = "Revoke";
      btnRevoke.addEventListener("click", () => revokeDevice(d.id, d.device_name));
      actions.appendChild(btnRevoke);
    }

    li.appendChild(info);
    li.appendChild(actions);
    els.devicesList.appendChild(li);
  }
}

// XSS-Safe Pending Requests Rendering
function renderPendingRequests(requests) {
  els.pendingRequestsList.innerHTML = "";
  if (requests.length === 0) {
    const emptyLi = document.createElement("li");
    emptyLi.className = "text-muted";
    emptyLi.textContent = "No pending device requests.";
    els.pendingRequestsList.appendChild(emptyLi);
    return;
  }

  for (const r of requests) {
    const li = document.createElement("li");
    li.className = "request-item";

    const title = document.createElement("div");
    const nameEl = document.createElement("strong");
    nameEl.textContent = r.new_device_name;

    const expEl = document.createElement("small");
    expEl.className = "text-muted";
    expEl.textContent = "Expires in 5 minutes";

    title.appendChild(nameEl);
    title.appendChild(document.createTextNode(` wants to connect (${r.action_type})`));
    title.appendChild(document.createElement("br"));
    title.appendChild(expEl);

    const inputCode = document.createElement("input");
    inputCode.type = "text";
    inputCode.className = "form-control form-control-sm";
    inputCode.placeholder = "Enter 6-digit code shown on new phone";
    inputCode.maxLength = 6;

    const btnApprove = document.createElement("button");
    btnApprove.className = "btn btn-success btn-sm";
    btnApprove.textContent = "Verify & Approve";
    btnApprove.addEventListener("click", () => approveDeviceRequest(r, inputCode.value.trim()));

    li.appendChild(title);
    li.appendChild(inputCode);
    li.appendChild(btnApprove);
    els.pendingRequestsList.appendChild(li);
  }
}

// Approve New Phone on Verified Device
async function approveDeviceRequest(req, code) {
  if (!code || code.length !== 6) {
    showAlert(els.devicesAlert, "Please enter the exact 6-digit code shown on the new phone.");
    return;
  }

  try {
    const codeHash = await CryptoUtils.sha256Hex(code);
    if (codeHash !== req.verification_code_hash) {
      showAlert(els.devicesAlert, "Incorrect 6-digit verification code. Please check the new phone's screen.");
      return;
    }

    // Step-up assertion to unwrap MEK
    const chRes = await apiFetch(`/api/v1/keys/new/challenge`, { method: "POST" });
    const chData = await chRes.json();
    if (!chRes.ok) throw new Error(chData.message || chData.error);

    const prfSaltBytes = CryptoUtils.base64ToBytes(chData.prf_salt);
    const reqOptions = WebAuthnHelper.prepareRequestOptions(chData.options.publicKey, prfSaltBytes);
    const assertion = await navigator.credentials.get({ publicKey: reqOptions });

    const passkeyKek = await getOrDerivePasskeyKek(assertion, prfSaltBytes, false);

    const rawMek = await CryptoUtils.unwrapMek(
      passkeyKek,
      CryptoUtils.base64ToBytes(chData.wrapped_mek),
      CryptoUtils.base64ToBytes(chData.wrapped_mek_iv)
    );

    // Ephemeral ECDH shared secret derivation
    const approverECDH = await CryptoUtils.generateECDHKeyPair();
    const newPhonePubBytes = CryptoUtils.base64ToBytes(req.new_device_ecdh_pub);
    const newPhonePubKey = await CryptoUtils.importECDHPublicKey(newPhonePubBytes);

    const sharedKey = await CryptoUtils.deriveTransferSharedKey(
      approverECDH.privateKey,
      newPhonePubKey,
      code
    );

    const { encryptedMek, transferIv } = await CryptoUtils.encryptMekTransfer(sharedKey, rawMek);
    CryptoUtils.zeroBuffer(rawMek);

    const approverPubBytes = await CryptoUtils.exportECDHPublicKey(approverECDH.publicKey);

    // Submit approval
    const appRes = await apiFetch(`/api/v1/devices/requests/${encodeURIComponent(req.id)}/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        step_up_id: chData.step_up_id,
        assertion: WebAuthnHelper.serializeAssertionResponse(assertion),
        approver_ecdh_pub: CryptoUtils.bytesToBase64Url(approverPubBytes),
        encrypted_mek_transfer: CryptoUtils.bytesToBase64Url(encryptedMek),
        transfer_iv: CryptoUtils.bytesToBase64Url(transferIv),
      }),
    });
    if (!appRes.ok) {
      const d = await appRes.json();
      throw new Error(d.message || d.error);
    }

    showAlert(els.devicesAlert, `Successfully approved ${req.new_device_name}!`, "success");
    loadDevicesAndRequests();
  } catch (err) {
    showAlert(els.devicesAlert, "Approval failed: " + err.message);
  }
}

// Start Add/Change Phone from New Phone
async function startPhoneHandshake(actionType) {
  const deviceName = prompt("Enter a name for this new phone (e.g. 'Pixel 9', 'iPhone 16'):");
  if (!deviceName) return;

  let replaceCredId = "";
  if (actionType === "change_phone" && state.activeCredId) {
    if (confirm("Replace currently active phone passkey with this new phone?")) {
      replaceCredId = state.activeCredId;
    }
  }

  try {
    const ecdhPair = await CryptoUtils.generateECDHKeyPair();
    const pubBytes = await CryptoUtils.exportECDHPublicKey(ecdhPair.publicKey);

    // Generate random 6-digit code
    const randomVals = crypto.getRandomValues(new Uint32Array(1));
    const code = String(100000 + (randomVals[0] % 900000));
    const codeHash = await CryptoUtils.sha256Hex(code);

    const reqRes = await fetch("/api/v1/devices/request", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: state.currentUser ? state.currentUser.username : prompt("Enter your username:"),
        action_type: actionType,
        replace_credential_id: replaceCredId,
        device_name: deviceName,
        new_device_ecdh_pub: CryptoUtils.bytesToBase64Url(pubBytes),
        verification_code_hash: codeHash,
      }),
    });
    const reqData = await reqRes.json();
    if (!reqRes.ok) throw new Error(reqData.message || reqData.error);

    state.pendingNewPhoneECDH = ecdhPair;
    state.pendingNewPhoneCode = code;
    state.pendingNewPhoneRequestId = reqData.request_id;

    els.newPhoneSection.style.display = "block";
    els.newPhoneCodeDisplay.textContent = `${code.slice(0, 3)} ${code.slice(3)}`;
    els.newPhoneStatusText.textContent = "Waiting for approval on your verified device...";

    // Poll status
    state.phonePollTimer = setInterval(async () => {
      try {
        const stRes = await fetch(`/api/v1/devices/requests/${encodeURIComponent(reqData.request_id)}/status`);
        const stData = await stRes.json();
        if (stData.status === "approved") {
          clearInterval(state.phonePollTimer);
          state.phonePollTimer = null;
          els.newPhoneStatusText.textContent = "Approved! Creating Passkey and completing transfer...";
          await completePhoneHandshake(stData);
        } else if (stData.status === "expired" || stData.status === "rejected") {
          clearInterval(state.phonePollTimer);
          state.phonePollTimer = null;
          els.newPhoneStatusText.textContent = `Request ${stData.status}.`;
        }
      } catch (e) {}
    }, 2000);
  } catch (err) {
    showAlert(els.devicesAlert, err.message);
  }
}

async function completePhoneHandshake(statusData) {
  try {
    const approverPubBytes = CryptoUtils.base64ToBytes(statusData.approver_ecdh_pub);
    const approverPubKey = await CryptoUtils.importECDHPublicKey(approverPubBytes);

    const sharedKey = await CryptoUtils.deriveTransferSharedKey(
      state.pendingNewPhoneECDH.privateKey,
      approverPubKey,
      state.pendingNewPhoneCode
    );

    const rawMek = await CryptoUtils.decryptMekTransfer(
      sharedKey,
      CryptoUtils.base64ToBytes(statusData.encrypted_mek_transfer),
      CryptoUtils.base64ToBytes(statusData.transfer_iv)
    );

    const prfSaltBytes = CryptoUtils.base64ToBytes(statusData.prf_salt);
    const creationOptions = WebAuthnHelper.prepareCreationOptions(
      statusData.reg_options.publicKey,
      prfSaltBytes
    );

    const credential = await navigator.credentials.create({ publicKey: creationOptions });

    const passkeyKek = await getOrDerivePasskeyKek(credential, prfSaltBytes, true);

    const { wrappedMek, wrappedMekIv } = await CryptoUtils.wrapMek(passkeyKek, rawMek);
    CryptoUtils.zeroBuffer(rawMek);

    const compRes = await fetch(`/api/v1/devices/requests/${encodeURIComponent(state.pendingNewPhoneRequestId)}/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        attestation: WebAuthnHelper.serializeCreationResponse(credential),
        wrapped_mek: CryptoUtils.bytesToBase64Url(wrappedMek),
        wrapped_mek_iv: CryptoUtils.bytesToBase64Url(wrappedMekIv),
      }),
    });
    const compData = await compRes.json();
    if (!compRes.ok) throw new Error(compData.message || compData.error);

    els.newPhoneStatusText.textContent = "Successfully enrolled and verified this device!";
    setTimeout(() => {
      els.newPhoneSection.style.display = "none";
      loadDevicesAndRequests();
    }, 2000);
  } catch (err) {
    showAlert(els.devicesAlert, "Handshake completion failed: " + err.message);
  }
}

els.btnAddPhone.addEventListener("click", () => startPhoneHandshake("add_phone"));
els.btnChangePhone.addEventListener("click", () => startPhoneHandshake("change_phone"));

async function revokeDevice(credIdHex, deviceName) {
  if (!confirm(`Revoke device "${deviceName}"? Passkey verification required.`)) return;
  try {
    const chRes = await apiFetch(`/api/v1/keys/new/challenge`, { method: "POST" });
    const chData = await chRes.json();
    if (!chRes.ok) throw new Error(chData.message || chData.error);

    const reqOptions = WebAuthnHelper.prepareRequestOptions(chData.options.publicKey);
    const assertion = await navigator.credentials.get({ publicKey: reqOptions });

    const revRes = await apiFetch(`/api/v1/devices/${encodeURIComponent(credIdHex)}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        step_up_id: chData.step_up_id,
        assertion: WebAuthnHelper.serializeAssertionResponse(assertion),
      }),
    });
    if (!revRes.ok) {
      const d = await revRes.json();
      throw new Error(d.message || d.error);
    }
    showAlert(els.devicesAlert, `Device ${deviceName} revoked.`, "info");
    loadDevicesAndRequests();
  } catch (err) {
    showAlert(els.devicesAlert, "Revocation failed: " + err.message);
  }
}

// Initial Boot
checkSealStatus();
