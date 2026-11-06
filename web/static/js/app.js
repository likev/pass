/**
 * Web Password & Key Manager - Main Application Logic
 */

import { CryptoUtils } from "./crypto.js";
import { WebAuthnHelper } from "./webauthn.js";
import { ClipboardGuard } from "./clipboard.js";
import { I18n } from "./i18n.js";
import { TOTPUtils } from "./totp.js";

// Key size limit: 10KB (10,240 bytes)
const MAX_KEY_SIZE_BYTES = 10 * 1024;

// Application State
const state = {
  csrfToken: null,
  currentUser: null,
  activeCredId: null,
  sealed: true,
  initialized: false,
  pendingPastedBytes: null, // Ephemeral Uint8Array for pasted key
  pendingTotpBytes: null, // Ephemeral Uint8Array for TOTP otpauth:// URI
  pendingTotpMeta: null, // { digits, period }
  selectedTypeFilter: "all", // "all" | "secret" | "totp"
  pendingNewPhoneECDH: null,
  pendingNewPhoneCode: null,
  pendingNewPhoneRequestId: null,
  phonePollTimer: null,
  approverPollTimer: null,
  selectedPairAction: "add_phone",
  cachedKeys: [],
  cachedDevices: [],
  cachedPendingRequests: [],
};

// UI Elements
const els = {
  bannerClipboard: document.getElementById("banner-clipboard"),
  clipboardText: document.getElementById("clipboard-text"),
  clipboardProgressBar: document.getElementById("clipboard-progress-bar"),
  btnClearClipboard: document.getElementById("btn-clear-clipboard"),

  btnLangEn: document.getElementById("btn-lang-en"),
  btnLangZh: document.getElementById("btn-lang-zh"),

  viewUnseal: document.getElementById("view-unseal"),
  viewAuth: document.getElementById("view-auth"),
  viewDashboard: document.getElementById("view-dashboard"),
  headerUserActions: document.getElementById("header-user-actions"),

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
  btnAuthPairPhone: document.getElementById("btn-auth-pair-phone"),

  // Dashboard & Single-Device Warning
  userDisplayName: document.getElementById("user-display-name"),
  devicesCountBadge: document.getElementById("devices-count-badge"),
  btnLogout: document.getElementById("btn-logout"),
  singleDeviceWarning: document.getElementById("single-device-warning"),
  btnWarningAddDevice: document.getElementById("btn-warning-add-device"),
  keysFilter: document.getElementById("keys-filter"),
  filterTypeAll: document.getElementById("filter-type-all"),
  filterTypeSecret: document.getElementById("filter-type-secret"),
  filterTypeTotp: document.getElementById("filter-type-totp"),
  keysCountBadge: document.getElementById("keys-count-badge"),
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
  tabTotp: document.getElementById("tab-totp"),
  sectionType: document.getElementById("section-type"),
  sectionPaste: document.getElementById("section-paste"),
  sectionGen: document.getElementById("section-gen"),
  sectionTotp: document.getElementById("section-totp"),
  keyTypePrimary: document.getElementById("key-type-primary"),
  keyTypeConfirm: document.getElementById("key-type-confirm"),
  pasteStatusBadge: document.getElementById("paste-status-badge"),
  btnPasteCapture: document.getElementById("btn-paste-capture"),
  genPreset: document.getElementById("gen-preset"),
  genLength: document.getElementById("gen-length"),
  genLengthVal: document.getElementById("gen-length-val"),
  genCopyCheckbox: document.getElementById("gen-copy-checkbox"),
  btnTotpCamera: document.getElementById("btn-totp-camera"),
  btnTotpCameraLabel: document.getElementById("btn-totp-camera-label"),
  btnTotpUpload: document.getElementById("btn-totp-upload"),
  totpQrFile: document.getElementById("totp-qr-file"),
  totpCameraBox: document.getElementById("totp-camera-box"),
  totpQrVideo: document.getElementById("totp-qr-video"),
  totpStatusBadge: document.getElementById("totp-status-badge"),
  totpSeedInput: document.getElementById("totp-seed-input"),
  btnSaveKey: document.getElementById("btn-save-key"),
  createKeyAlert: document.getElementById("create-key-alert"),

  // Devices View
  btnOpenDevices: document.getElementById("btn-open-devices"),
  modalDevices: document.getElementById("modal-devices"),
  modalDevicesTitle: document.getElementById("modal-devices-title"),
  modalDevicesSubtitle: document.getElementById("modal-devices-subtitle"),
  btnCloseDevices: document.getElementById("btn-close-devices"),
  unauthNewDeviceView: document.getElementById("unauth-new-device-view"),
  verifiedDeviceView: document.getElementById("verified-device-view"),
  modalSingleDeviceTip: document.getElementById("modal-single-device-tip"),
  pairUsername: document.getElementById("pair-username"),
  pairDeviceName: document.getElementById("pair-device-name"),
  btnStartPairing: document.getElementById("btn-start-pairing"),
  btnRefreshRequests: document.getElementById("btn-refresh-requests"),
  devicesList: document.getElementById("devices-list"),
  pendingRequestsList: document.getElementById("pending-requests-list"),
  btnAddPhone: document.getElementById("btn-add-phone"),
  btnChangePhone: document.getElementById("btn-change-phone"),
  newPhoneSection: document.getElementById("new-phone-section"),
  newPhoneCodeDisplay: document.getElementById("new-phone-code-display"),
  newPhoneStatusText: document.getElementById("new-phone-status-text"),
  devicesAlert: document.getElementById("devices-alert"),
};

// ===================== Language Switcher & i18n Init =====================

function syncLangButtons() {
  if (els.btnLangEn) {
    els.btnLangEn.classList.toggle("active", I18n.lang === "en");
  }
  if (els.btnLangZh) {
    els.btnLangZh.classList.toggle("active", I18n.lang === "zh");
  }
}

if (els.btnLangEn) {
  els.btnLangEn.addEventListener("click", () => I18n.setLang("en"));
}
if (els.btnLangZh) {
  els.btnLangZh.addEventListener("click", () => I18n.setLang("zh"));
}

I18n.onChange(() => {
  syncLangButtons();
  updateUnsealCopy();
  updatePasteBadgeCopy();
  updateTotpBadgeCopy();
  updateDevicesModalHeaderCopy();
  if (state.currentUser) {
    renderKeys(state.cachedKeys);
    renderDevices(state.cachedDevices);
    renderPendingRequests(state.cachedPendingRequests);
  }
});

// Apply initial detected language immediately
I18n.applyDOMTranslations();
syncLangButtons();

// ===================== Clipboard Auto-Clear Guard =====================

ClipboardGuard.init(
  (remainingMs, reason, pendingClear) => {
    if (pendingClear) {
      els.bannerClipboard.style.display = "flex";
      els.clipboardText.textContent = I18n.t("clipboardPendingWipe");
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
    const actionLabel =
      reason === "pasted"
        ? I18n.t("clipboardPastedLabel")
        : I18n.t("clipboardCopiedLabel");
    els.clipboardText.textContent = I18n.t("clipboardCountdown", {
      label: actionLabel,
      time: timeStr,
    });
    const percent = ((180000 - remainingMs) / 180000) * 100;
    els.clipboardProgressBar.style.width = `${percent}%`;
  },
  () => {
    els.bannerClipboard.style.display = "none";
    showAlert(els.keysAlert, I18n.t("clipboardAutoCleared"), "info");
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
            extensions: {
              prf: {
                eval: {
                  first: WebAuthnHelper.toArrayBuffer(prfSaltBytes),
                },
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

// ===================== Server Seal Status =====================

function updateUnsealCopy() {
  if (!state.sealed) return;
  if (!state.initialized) {
    els.unsealTitle.textContent = I18n.t("unsealInitTitle");
    els.unsealDesc.textContent = I18n.t("unsealInitDesc");
    els.unsealPassConfirmRow.style.display = "block";
    els.btnUnsealSubmit.textContent = I18n.t("unsealInitBtn");
  } else {
    els.unsealTitle.textContent = I18n.t("unsealSealedTitle");
    els.unsealDesc.textContent = I18n.t("unsealSealedDesc");
    els.unsealPassConfirmRow.style.display = "none";
    els.btnUnsealSubmit.textContent = I18n.t("unsealSealedBtn");
  }
}

async function checkSealStatus() {
  try {
    const res = await fetch("/api/v1/admin/seal-status", { cache: "no-store" });
    const data = await res.json();
    state.initialized = data.initialized;
    state.sealed = !data.unsealed;

    if (state.sealed) {
      showView("unseal");
      updateUnsealCopy();
    } else {
      await checkAuthStatus();
    }
  } catch (err) {
    showView("unseal");
    showAlert(els.unsealAlert, I18n.t("unsealConnectError", { err: err.message }));
  }
}

els.btnUnsealSubmit.addEventListener("click", async () => {
  hideAlert(els.unsealAlert);
  const pass = els.unsealPass.value;
  if (pass.length < 12) {
    showAlert(els.unsealAlert, I18n.t("unsealMinLenError"));
    return;
  }

  const payload = { passphrase: pass };
  if (!state.initialized) {
    const confirm = els.unsealPassConfirm.value;
    if (pass !== confirm) {
      showAlert(els.unsealAlert, I18n.t("unsealMismatchError"));
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

// ===================== Auth & Dashboard Entry =====================

async function enterDashboard(user) {
  state.currentUser = user;
  showView("dashboard");
  els.userDisplayName.textContent = user.display_name || user.username;
  await Promise.all([loadKeys(), checkDeviceSafety()]);
}

async function checkAuthStatus() {
  try {
    const res = await apiFetch("/api/v1/auth/me");
    if (res.ok) {
      const data = await res.json();
      state.activeCredId = data.credential_id;
      state.csrfToken = data.csrf_token;
      await enterDashboard(data.user);
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
  if (els.headerUserActions) {
    els.headerUserActions.style.display = view === "dashboard" ? "flex" : "none";
  }
}

// Check how many verified devices the user has; warn if <= 1
async function checkDeviceSafety() {
  if (!state.currentUser) return;
  try {
    const res = await apiFetch("/api/v1/devices");
    if (!res.ok) return;
    const data = await res.json();
    const devices = data.devices || [];
    state.cachedDevices = devices;
    updateSingleDeviceWarning(devices);
  } catch (_) {}
}

function updateSingleDeviceWarning(devices) {
  const verifiedCount = (devices || []).filter((d) => d.status === "verified").length;
  const isSingleDevice = verifiedCount <= 1;

  if (els.singleDeviceWarning) {
    els.singleDeviceWarning.style.display = isSingleDevice ? "flex" : "none";
  }
  if (els.modalSingleDeviceTip) {
    els.modalSingleDeviceTip.style.display = state.currentUser && isSingleDevice ? "flex" : "none";
  }
  if (els.devicesCountBadge) {
    els.devicesCountBadge.style.display = verifiedCount > 0 ? "inline-block" : "none";
    els.devicesCountBadge.textContent = String(verifiedCount);
    els.devicesCountBadge.classList.toggle("count-warning", isSingleDevice);
  }
}

if (els.btnWarningAddDevice) {
  els.btnWarningAddDevice.addEventListener("click", () => {
    openDevicesModal();
  });
}

// ===================== Passkey Registration & Login =====================

els.btnRegister.addEventListener("click", async () => {
  hideAlert(els.authAlert);
  const username = els.regUsername.value.trim();
  const displayName = els.regDisplayName.value.trim() || username;
  const deviceName = els.regDeviceName.value.trim() || I18n.t("defaultDeviceName");

  if (!username) {
    showAlert(els.authAlert, I18n.t("regUsernameRequired"));
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
    state.activeCredId =
      finishData.credential_id || WebAuthnHelper.arrayBufferToBase64(credential.rawId);
    await enterDashboard(finishData.user);
  } catch (err) {
    showAlert(els.authAlert, I18n.t("regFailed", { err: err.message }));
  }
});

els.btnLogin.addEventListener("click", async () => {
  hideAlert(els.authAlert);
  const username = els.loginUsername.value.trim();
  if (!username) {
    showAlert(els.authAlert, I18n.t("loginUsernameRequired"));
    els.loginUsername.focus();
    return;
  }

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
    state.activeCredId =
      finishData.credential_id || WebAuthnHelper.arrayBufferToBase64(assertion.rawId);
    await enterDashboard(finishData.user);
  } catch (err) {
    showAlert(els.authAlert, I18n.t("loginFailed", { err: err.message }));
  }
});

els.btnLogout.addEventListener("click", async () => {
  await apiFetch("/api/v1/auth/logout", { method: "POST" });
  await ClipboardGuard.clearNow();
  state.currentUser = null;
  state.activeCredId = null;
  state.csrfToken = null;
  state.cachedKeys = [];
  state.cachedDevices = [];
  state.cachedPendingRequests = [];
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

function setTypeFilter(type) {
  state.selectedTypeFilter = type;
  if (els.filterTypeAll) els.filterTypeAll.classList.toggle("active", type === "all");
  if (els.filterTypeSecret) els.filterTypeSecret.classList.toggle("active", type === "secret");
  if (els.filterTypeTotp) els.filterTypeTotp.classList.toggle("active", type === "totp");
  renderKeys(state.cachedKeys);
}

if (els.filterTypeAll) els.filterTypeAll.addEventListener("click", () => setTypeFilter("all"));
if (els.filterTypeSecret) els.filterTypeSecret.addEventListener("click", () => setTypeFilter("secret"));
if (els.filterTypeTotp) els.filterTypeTotp.addEventListener("click", () => setTypeFilter("totp"));

async function loadKeys(query = "") {
  try {
    const res = await apiFetch(`/api/v1/keys?q=${encodeURIComponent(query)}`);
    if (!res.ok) return;
    const data = await res.json();
    state.cachedKeys = data.keys || [];
    renderKeys(state.cachedKeys);
  } catch (err) {
    showAlert(els.keysAlert, I18n.t("loadKeysFailed", { err: err.message }));
  }
}

function renderKeys(keys) {
  els.keysList.innerHTML = "";
  const filteredKeys = (keys || []).filter((k) => {
    const kType = k.key_type === "totp" ? "totp" : "secret";
    if (state.selectedTypeFilter === "all") return true;
    return kType === state.selectedTypeFilter;
  });

  if (els.keysCountBadge) {
    els.keysCountBadge.textContent = String(filteredKeys.length);
  }
  if (filteredKeys.length === 0) {
    const emptyLi = document.createElement("li");
    emptyLi.className = "empty-list";
    emptyLi.textContent = I18n.t("emptyKeysList");
    els.keysList.appendChild(emptyLi);
    return;
  }

  const locale = I18n.lang === "zh" ? "zh-CN" : "en-US";
  for (const k of filteredKeys) {
    const isTotp = k.key_type === "totp";
    const li = document.createElement("li");
    li.className = "key-item";

    const info = document.createElement("div");
    info.className = "key-info";

    const titleRow = document.createElement("div");
    titleRow.className = "key-title-row";

    const name = document.createElement("span");
    name.className = "key-title";
    name.textContent = k.name;
    titleRow.appendChild(name);

    if (isTotp) {
      const badge = document.createElement("span");
      badge.className = "badge badge-totp";
      badge.textContent = I18n.t("badgeTotp");
      titleRow.appendChild(badge);
    }

    const date = document.createElement("span");
    date.className = "key-date";
    date.textContent = I18n.t("keyUpdatedPrefix", {
      date: new Date(k.updated_at).toLocaleString(locale),
    });

    info.appendChild(titleRow);
    info.appendChild(date);

    const actions = document.createElement("div");
    actions.className = "key-actions";

    const btnCopy = document.createElement("button");
    btnCopy.className = isTotp ? "btn btn-primary btn-sm btn-totp-copy" : "btn btn-primary btn-sm";
    btnCopy.textContent = isTotp ? I18n.t("btnCopyTotp") : I18n.t("btnCopyKey");
    btnCopy.addEventListener("click", () => copySingleKey(k.id, k.name, k.key_type));

    const btnDelete = document.createElement("button");
    btnDelete.className = "btn btn-danger btn-sm";
    btnDelete.textContent = I18n.t("btnDeleteKey");
    btnDelete.addEventListener("click", () => deleteKey(k.id, k.name));

    actions.appendChild(btnCopy);
    actions.appendChild(btnDelete);

    li.appendChild(info);
    li.appendChild(actions);
    els.keysList.appendChild(li);
  }
}

// Single-Key Retrieval & Direct Clipboard Decryption (or 6-Digit TOTP Code Generation)
// Uses writeViaPromise so browser preserves transient user activation across WebAuthn + retrieve fetch
async function copySingleKey(keyId, keyName, keyType = "secret") {
  hideAlert(els.keysAlert);
  let totpRemainingSec = null;
  let resolvedAsTotp = keyType === "totp";
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

      if (keyData.key_type === "totp") {
        resolvedAsTotp = true;
      }

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
        if (resolvedAsTotp) {
          const totp = await TOTPUtils.generateTotpFromBytes(plaintextBytes);
          totpRemainingSec = totp.remainingSeconds;
          return new Blob([totp.code], { type: "text/plain" });
        }
        return new Blob([plaintextBytes], { type: "text/plain" });
      } finally {
        CryptoUtils.zeroBuffer(plaintextBytes);
      }
    })();

    await ClipboardGuard.writeViaPromise(keyBlobPromise, "copied");
    if (resolvedAsTotp) {
      showAlert(
        els.keysAlert,
        I18n.t("totpCopiedAlert", { name: keyName, sec: totpRemainingSec || 30 }),
        "success"
      );
    } else {
      showAlert(els.keysAlert, I18n.t("keyCopiedAlert", { name: keyName }), "success");
    }
  } catch (err) {
    showAlert(els.keysAlert, I18n.t("keyCopyFailed", { err: err.message }));
  }
}

async function deleteKey(keyId, keyName) {
  if (!confirm(I18n.t("confirmDeleteKey", { name: keyName }))) {
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
    showAlert(els.keysAlert, I18n.t("keyDeletedAlert", { name: keyName }), "info");
    loadKeys(els.keysFilter.value);
  } catch (err) {
    showAlert(els.keysAlert, I18n.t("keyDeleteFailed", { err: err.message }));
  }
}

// ===================== 4-Mode Key & TOTP Creation =====================

let activeMode = "type"; // "type" | "paste" | "gen" | "totp"

els.btnOpenCreateKey.addEventListener("click", () => {
  resetCreateKeyModal();
  if (state.selectedTypeFilter === "totp") {
    switchMode("totp");
  }
  els.modalCreateKey.style.display = "flex";
});

els.btnCloseCreateKey.addEventListener("click", () => {
  resetCreateKeyModal();
  els.modalCreateKey.style.display = "none";
});

function updatePasteBadgeCopy() {
  if (!els.pasteStatusBadge) return;
  if (state.pendingPastedBytes && state.pendingPastedBytes.length > 0) {
    els.pasteStatusBadge.textContent = I18n.t("pasteStatusCaptured", {
      bytes: state.pendingPastedBytes.length,
    });
    els.pasteStatusBadge.className = "badge badge-success";
  } else {
    els.pasteStatusBadge.textContent = I18n.t("pasteStatusEmpty");
    els.pasteStatusBadge.className = "badge badge-neutral";
  }
}

function updateTotpBadgeCopy() {
  if (!els.totpStatusBadge) return;
  if (state.pendingTotpBytes && state.pendingTotpBytes.length > 0 && state.pendingTotpMeta) {
    els.totpStatusBadge.textContent = I18n.t("totpStatusCaptured", {
      digits: state.pendingTotpMeta.digits,
      period: state.pendingTotpMeta.period,
    });
    els.totpStatusBadge.className = "badge badge-success";
  } else {
    els.totpStatusBadge.textContent = I18n.t("totpStatusEmpty");
    els.totpStatusBadge.className = "badge badge-neutral";
  }
  if (els.btnTotpCameraLabel) {
    els.btnTotpCameraLabel.textContent = TOTPUtils.isCameraActive()
      ? I18n.t("btnTotpStopCamera")
      : I18n.t("btnTotpScanCamera");
  }
}

function stopTotpCameraUI() {
  TOTPUtils.stopCameraScanner();
  if (els.totpCameraBox) els.totpCameraBox.style.display = "none";
  if (els.btnTotpCameraLabel) {
    els.btnTotpCameraLabel.textContent = I18n.t("btnTotpScanCamera");
  }
}

function captureTotpInput(rawText, fromQr = false) {
  const parsed = TOTPUtils.parseTotpInput(rawText);
  if (state.pendingTotpBytes) {
    CryptoUtils.zeroBuffer(state.pendingTotpBytes);
  }
  state.pendingTotpBytes = new TextEncoder().encode(parsed.canonicalUri);
  state.pendingTotpMeta = {
    digits: parsed.digits,
    period: parsed.period,
  };
  if (parsed.suggestedName && !els.keyName.value.trim()) {
    els.keyName.value = parsed.suggestedName;
  }
  if (els.totpSeedInput) {
    els.totpSeedInput.value = "";
  }
  updateTotpBadgeCopy();
  if (fromQr) {
    showAlert(els.createKeyAlert, I18n.t("totpQrScanSuccess"), "success");
  } else {
    hideAlert(els.createKeyAlert);
  }
}

function resetCreateKeyModal() {
  hideAlert(els.createKeyAlert);
  stopTotpCameraUI();
  els.keyName.value = "";
  els.keyTypePrimary.value = "";
  els.keyTypeConfirm.value = "";
  if (els.totpSeedInput) els.totpSeedInput.value = "";
  if (els.totpQrFile) els.totpQrFile.value = "";
  if (state.pendingPastedBytes) {
    CryptoUtils.zeroBuffer(state.pendingPastedBytes);
    state.pendingPastedBytes = null;
  }
  if (state.pendingTotpBytes) {
    CryptoUtils.zeroBuffer(state.pendingTotpBytes);
    state.pendingTotpBytes = null;
  }
  state.pendingTotpMeta = null;
  updatePasteBadgeCopy();
  updateTotpBadgeCopy();
  switchMode("type");
}

function switchMode(mode) {
  activeMode = mode;
  hideAlert(els.createKeyAlert);
  if (mode !== "totp") {
    stopTotpCameraUI();
  }
  els.tabType.className = mode === "type" ? "tab active" : "tab";
  els.tabPaste.className = mode === "paste" ? "tab active" : "tab";
  els.tabGen.className = mode === "gen" ? "tab active" : "tab";
  if (els.tabTotp) els.tabTotp.className = mode === "totp" ? "tab active" : "tab";

  els.sectionType.style.display = mode === "type" ? "block" : "none";
  els.sectionPaste.style.display = mode === "paste" ? "block" : "none";
  els.sectionGen.style.display = mode === "gen" ? "block" : "none";
  if (els.sectionTotp) els.sectionTotp.style.display = mode === "totp" ? "block" : "none";
}

els.tabType.addEventListener("click", () => switchMode("type"));
els.tabPaste.addEventListener("click", () => switchMode("paste"));
els.tabGen.addEventListener("click", () => switchMode("gen"));
if (els.tabTotp) els.tabTotp.addEventListener("click", () => switchMode("totp"));

// TOTP Camera Scanner & QR Image Upload
if (els.btnTotpCamera) {
  els.btnTotpCamera.addEventListener("click", async () => {
    hideAlert(els.createKeyAlert);
    if (TOTPUtils.isCameraActive()) {
      stopTotpCameraUI();
      return;
    }
    try {
      els.totpCameraBox.style.display = "block";
      els.btnTotpCameraLabel.textContent = I18n.t("btnTotpStopCamera");
      await TOTPUtils.startCameraScanner(
        els.totpQrVideo,
        (decodedText) => {
          stopTotpCameraUI();
          try {
            captureTotpInput(decodedText, true);
          } catch (err) {
            showAlert(els.createKeyAlert, err.message);
          }
        },
        () => {}
      );
    } catch (err) {
      stopTotpCameraUI();
      showAlert(els.createKeyAlert, err.message);
    }
  });
}

if (els.btnTotpUpload && els.totpQrFile) {
  els.btnTotpUpload.addEventListener("click", () => {
    els.totpQrFile.click();
  });
  els.totpQrFile.addEventListener("change", async () => {
    const file = els.totpQrFile.files && els.totpQrFile.files[0];
    els.totpQrFile.value = "";
    if (!file) return;
    hideAlert(els.createKeyAlert);
    try {
      const decodedText = await TOTPUtils.decodeQrFromFile(file);
      captureTotpInput(decodedText, true);
    } catch (err) {
      showAlert(els.createKeyAlert, err.message);
    }
  });
}

if (els.totpSeedInput) {
  els.totpSeedInput.addEventListener("paste", (e) => {
    const text = e.clipboardData ? e.clipboardData.getData("text/plain") : "";
    if (text && text.trim()) {
      e.preventDefault();
      try {
        captureTotpInput(text, false);
        ClipboardGuard.scheduleClear(180 * 1000, "pasted");
      } catch (err) {
        showAlert(els.createKeyAlert, err.message);
      }
    }
  });
}

// Block pasting on Confirm Input so user actually types twice
els.keyTypeConfirm.addEventListener("paste", (e) => {
  e.preventDefault();
  showAlert(els.createKeyAlert, I18n.t("pasteDisabledConfirmAlert"));
});
els.keyTypeConfirm.addEventListener("drop", (e) => e.preventDefault());

// Validate typing length in real-time
els.keyTypePrimary.addEventListener("input", () => {
  const bytes = new TextEncoder().encode(els.keyTypePrimary.value);
  if (bytes.length > MAX_KEY_SIZE_BYTES) {
    showAlert(els.createKeyAlert, I18n.t("keyExceedsLimitAlert", { max: MAX_KEY_SIZE_BYTES }));
  } else {
    hideAlert(els.createKeyAlert);
  }
});

els.keyTypeConfirm.addEventListener("input", () => {
  const bytes = new TextEncoder().encode(els.keyTypeConfirm.value);
  if (bytes.length > MAX_KEY_SIZE_BYTES) {
    showAlert(els.createKeyAlert, I18n.t("keyExceedsLimitAlert", { max: MAX_KEY_SIZE_BYTES }));
  } else {
    const primaryBytes = new TextEncoder().encode(els.keyTypePrimary.value);
    if (primaryBytes.length <= MAX_KEY_SIZE_BYTES) {
      hideAlert(els.createKeyAlert);
    }
  }
});

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
  const encoded = new TextEncoder().encode(text);
  if (encoded.length > MAX_KEY_SIZE_BYTES) {
    if (state.pendingPastedBytes) {
      CryptoUtils.zeroBuffer(state.pendingPastedBytes);
      state.pendingPastedBytes = null;
    }
    updatePasteBadgeCopy();
    showAlert(els.createKeyAlert, I18n.t("keyExceedsLimitAlert", { max: MAX_KEY_SIZE_BYTES }));
    return;
  }
  if (state.pendingPastedBytes) {
    CryptoUtils.zeroBuffer(state.pendingPastedBytes);
  }
  state.pendingPastedBytes = encoded;
  updatePasteBadgeCopy();
  // Activate 3-minute clear countdown because user pasted from clipboard
  ClipboardGuard.scheduleClear(180 * 1000, "pasted");
}

els.btnPasteCapture.addEventListener("click", async () => {
  try {
    const text = await navigator.clipboard.readText();
    await capturePasteDirect(text);
  } catch (err) {
    showAlert(els.createKeyAlert, I18n.t("clipboardReadDeniedAlert"));
  }
});

window.addEventListener("paste", async (e) => {
  if (els.modalCreateKey.style.display === "flex") {
    if (activeMode === "paste") {
      e.preventDefault();
      const text = e.clipboardData.getData("text/plain");
      await capturePasteDirect(text);
    } else if (activeMode === "totp") {
      const files = e.clipboardData && e.clipboardData.files;
      if (files && files.length > 0 && files[0].type.startsWith("image/")) {
        e.preventDefault();
        try {
          const decodedText = await TOTPUtils.decodeQrFromFile(files[0]);
          captureTotpInput(decodedText, true);
        } catch (err) {
          showAlert(els.createKeyAlert, err.message);
        }
      }
    }
  }
});

els.genLength.addEventListener("input", () => {
  els.genLengthVal.textContent = els.genLength.value;
});

// Submit Create Key
els.btnSaveKey.addEventListener("click", async () => {
  hideAlert(els.createKeyAlert);
  // If user is in TOTP mode and scanned QR / typed seed with a suggested name before filling keyName
  if (activeMode === "totp" && els.totpSeedInput && els.totpSeedInput.value.trim()) {
    try {
      captureTotpInput(els.totpSeedInput.value.trim(), false);
    } catch (err) {
      showAlert(els.createKeyAlert, err.message);
      return;
    }
  }

  const name = els.keyName.value.trim();
  if (!name) {
    showAlert(els.createKeyAlert, I18n.t("keyNameRequiredAlert"));
    return;
  }

  let plaintextBytes = null;
  let genClipboardBytes = null;
  const isTotpKey = activeMode === "totp";

  try {
    if (activeMode === "type") {
      const p1 = els.keyTypePrimary.value;
      const p2 = els.keyTypeConfirm.value;
      if (!p1) {
        showAlert(els.createKeyAlert, I18n.t("keyEnterRequiredAlert"));
        return;
      }

      const buf1 = new TextEncoder().encode(p1);
      const buf2 = new TextEncoder().encode(p2);

      // Immediately clear DOM inputs
      els.keyTypePrimary.value = "";
      els.keyTypeConfirm.value = "";

      if (buf1.length > MAX_KEY_SIZE_BYTES || buf2.length > MAX_KEY_SIZE_BYTES) {
        CryptoUtils.zeroBuffer(buf1);
        CryptoUtils.zeroBuffer(buf2);
        showAlert(els.createKeyAlert, I18n.t("keyExceedsLimitAlert", { max: MAX_KEY_SIZE_BYTES }));
        return;
      }

      const match = CryptoUtils.constantTimeCompare(buf1, buf2);
      CryptoUtils.zeroBuffer(buf2);

      if (!match) {
        CryptoUtils.zeroBuffer(buf1);
        showAlert(els.createKeyAlert, I18n.t("keyMismatchAlert"));
        return;
      }
      plaintextBytes = buf1;
    } else if (activeMode === "paste") {
      if (!state.pendingPastedBytes || state.pendingPastedBytes.length === 0) {
        showAlert(els.createKeyAlert, I18n.t("noPasteCapturedAlert"));
        return;
      }
      if (state.pendingPastedBytes.length > MAX_KEY_SIZE_BYTES) {
        CryptoUtils.zeroBuffer(state.pendingPastedBytes);
        state.pendingPastedBytes = null;
        showAlert(els.createKeyAlert, I18n.t("keyExceedsLimitAlert", { max: MAX_KEY_SIZE_BYTES }));
        return;
      }
      plaintextBytes = state.pendingPastedBytes;
      state.pendingPastedBytes = null;
    } else if (activeMode === "gen") {
      const mode = els.genPreset.value;
      const length = parseInt(els.genLength.value, 10);
      if (isNaN(length) || length <= 0) {
        showAlert(els.createKeyAlert, I18n.t("invalidGenLengthAlert"));
        return;
      }
      if (length > MAX_KEY_SIZE_BYTES) {
        showAlert(els.createKeyAlert, I18n.t("keyExceedsLimitAlert", { max: MAX_KEY_SIZE_BYTES }));
        return;
      }
      plaintextBytes = CryptoUtils.generateSecureKey(mode, length);
      if (plaintextBytes.length > MAX_KEY_SIZE_BYTES) {
        CryptoUtils.zeroBuffer(plaintextBytes);
        showAlert(els.createKeyAlert, I18n.t("keyExceedsLimitAlert", { max: MAX_KEY_SIZE_BYTES }));
        return;
      }

      if (els.genCopyCheckbox.checked) {
        // Prepare defensive copy to write to clipboard ONLY after successful save
        genClipboardBytes = new Uint8Array(plaintextBytes.length);
        genClipboardBytes.set(plaintextBytes);
      }
    } else if (activeMode === "totp") {
      if (!state.pendingTotpBytes || state.pendingTotpBytes.length === 0) {
        showAlert(els.createKeyAlert, I18n.t("totpStatusEmpty"));
        return;
      }
      plaintextBytes = state.pendingTotpBytes;
      state.pendingTotpBytes = null;
      state.pendingTotpMeta = null;
    }

    if (!plaintextBytes || plaintextBytes.length === 0) {
      showAlert(els.createKeyAlert, I18n.t("emptyPayloadAlert"));
      return;
    }

    if (plaintextBytes.length > MAX_KEY_SIZE_BYTES) {
      CryptoUtils.zeroBuffer(plaintextBytes);
      if (genClipboardBytes) CryptoUtils.zeroBuffer(genClipboardBytes);
      showAlert(els.createKeyAlert, I18n.t("keyExceedsLimitAlert", { max: MAX_KEY_SIZE_BYTES }));
      return;
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
        key_type: isTotpKey ? "totp" : "secret",
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
    showAlert(
      els.keysAlert,
      I18n.t(isTotpKey ? "totpSavedAlert" : "keySavedAlert", { name }),
      "success"
    );
    loadKeys(els.keysFilter.value);
  } catch (err) {
    if (plaintextBytes) CryptoUtils.zeroBuffer(plaintextBytes);
    if (genClipboardBytes) CryptoUtils.zeroBuffer(genClipboardBytes);
    showAlert(els.createKeyAlert, I18n.t("keySaveFailedAlert", { err: err.message }));
  }
});

// ===================== Devices & Verified-Device Phone Enrollment =====================

function updateDevicesModalHeaderCopy() {
  if (!els.modalDevicesTitle || !els.modalDevicesSubtitle) return;
  if (state.currentUser) {
    els.modalDevicesTitle.textContent = I18n.t("modalDevicesTitle");
    els.modalDevicesSubtitle.textContent = I18n.t("modalDevicesSubtitle");
  } else {
    els.modalDevicesTitle.textContent = I18n.t("modalPairNewDeviceTitle");
    els.modalDevicesSubtitle.textContent = I18n.t("modalPairNewDeviceSubtitle");
  }
}

function setPairActionMode(mode) {
  state.selectedPairAction = mode;
  if (els.btnAddPhone) {
    els.btnAddPhone.className = mode === "add_phone" ? "tab active" : "tab";
  }
  if (els.btnChangePhone) {
    els.btnChangePhone.className = mode === "change_phone" ? "tab active" : "tab";
  }
}

function openDevicesModal() {
  hideAlert(els.devicesAlert);
  updateDevicesModalHeaderCopy();

  if (state.currentUser) {
    // Current device is ALREADY verified -> show Approver & Device Management view ONLY
    if (els.unauthNewDeviceView) els.unauthNewDeviceView.style.display = "none";
    if (els.verifiedDeviceView) els.verifiedDeviceView.style.display = "block";
    els.modalDevices.style.display = "flex";
    loadDevicesAndRequests();

    if (state.approverPollTimer) {
      clearInterval(state.approverPollTimer);
    }
    state.approverPollTimer = setInterval(() => {
      if (els.modalDevices.style.display === "flex" && state.currentUser) {
        loadDevicesAndRequests();
      }
    }, 3000);
  } else {
    // Unauthenticated new device -> show New Device Pairing Initiator view ONLY
    if (els.verifiedDeviceView) els.verifiedDeviceView.style.display = "none";
    if (els.unauthNewDeviceView) els.unauthNewDeviceView.style.display = "block";
    if (els.pairUsername && !els.pairUsername.value && els.loginUsername.value.trim()) {
      els.pairUsername.value = els.loginUsername.value.trim();
    }
    setPairActionMode(state.selectedPairAction || "add_phone");
    els.modalDevices.style.display = "flex";
  }
}

function closeDevicesModal() {
  if (state.phonePollTimer) {
    clearInterval(state.phonePollTimer);
    state.phonePollTimer = null;
  }
  if (state.approverPollTimer) {
    clearInterval(state.approverPollTimer);
    state.approverPollTimer = null;
  }
  els.modalDevices.style.display = "none";
}

els.btnOpenDevices.addEventListener("click", () => {
  openDevicesModal();
});

if (els.btnAuthPairPhone) {
  els.btnAuthPairPhone.addEventListener("click", () => {
    openDevicesModal();
  });
}

if (els.btnRefreshRequests) {
  els.btnRefreshRequests.addEventListener("click", () => {
    loadDevicesAndRequests();
  });
}

els.btnCloseDevices.addEventListener("click", () => {
  closeDevicesModal();
});

async function loadDevicesAndRequests() {
  if (!state.currentUser) {
    return;
  }
  try {
    const devRes = await apiFetch("/api/v1/devices");
    if (devRes.ok) {
      const devData = await devRes.json();
      state.cachedDevices = devData.devices || [];
      renderDevices(state.cachedDevices);
      updateSingleDeviceWarning(state.cachedDevices);
    }

    const reqRes = await apiFetch("/api/v1/devices/requests/pending");
    if (reqRes.ok) {
      const reqData = await reqRes.json();
      state.cachedPendingRequests = reqData.requests || [];
      renderPendingRequests(state.cachedPendingRequests);
    }
  } catch (err) {
    showAlert(els.devicesAlert, err.message);
  }
}

// XSS-Safe Device Rendering using textContent and DOM APIs
function renderDevices(devices) {
  els.devicesList.innerHTML = "";
  const locale = I18n.lang === "zh" ? "zh-CN" : "en-US";
  const verifiedTotal = devices.filter((x) => x.status === "verified").length;

  for (const d of devices) {
    const li = document.createElement("li");
    li.className = "device-item";

    const info = document.createElement("div");
    const nameEl = document.createElement("strong");
    nameEl.textContent = d.device_name;

    const badge = document.createElement("span");
    badge.className = `badge badge-${d.status === "verified" ? "success" : "neutral"}`;
    badge.textContent =
      d.status === "verified" ? I18n.t("statusVerified") : I18n.t("statusRevoked");

    info.appendChild(nameEl);
    info.appendChild(document.createTextNode(" "));
    info.appendChild(badge);

    if (state.activeCredId && d.id === state.activeCredId) {
      const currentBadge = document.createElement("span");
      currentBadge.className = "badge badge-primary";
      currentBadge.textContent = I18n.t("deviceCurrentBadge");
      info.appendChild(document.createTextNode(" "));
      info.appendChild(currentBadge);
    }

    const dateEl = document.createElement("small");
    dateEl.className = "text-muted";
    dateEl.textContent = I18n.t("enrolledDatePrefix", {
      date: new Date(d.created_at).toLocaleDateString(locale),
    });

    info.appendChild(document.createElement("br"));
    info.appendChild(dateEl);

    const actions = document.createElement("div");
    if (d.status === "verified" && verifiedTotal > 1) {
      const btnRevoke = document.createElement("button");
      btnRevoke.className = "btn btn-danger btn-sm";
      btnRevoke.textContent = I18n.t("btnRevoke");
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
    emptyLi.className = "text-muted small";
    emptyLi.textContent = I18n.t("noPendingRequests");
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
    expEl.textContent = I18n.t("expiresIn5Min");

    const actionDesc =
      r.action_type === "change_phone"
        ? I18n.t("wantsToConnectReplace")
        : I18n.t("wantsToConnectAdd");

    title.appendChild(nameEl);
    title.appendChild(document.createTextNode(` ${actionDesc}`));
    title.appendChild(document.createElement("br"));
    title.appendChild(expEl);

    const controls = document.createElement("div");
    controls.className = "request-controls";

    const inputCode = document.createElement("input");
    inputCode.type = "text";
    inputCode.className = "form-control form-control-sm";
    inputCode.placeholder = I18n.t("inputCodePlaceholder");
    inputCode.maxLength = 6;

    const btnApprove = document.createElement("button");
    btnApprove.className = "btn btn-success btn-sm";
    btnApprove.textContent = I18n.t("btnVerifyApprove");
    btnApprove.addEventListener("click", () => approveDeviceRequest(r, inputCode.value.trim()));

    controls.appendChild(inputCode);
    controls.appendChild(btnApprove);

    li.appendChild(title);
    li.appendChild(controls);
    els.pendingRequestsList.appendChild(li);
  }
}

// Approve New Phone on Verified Device
async function approveDeviceRequest(req, code) {
  if (!code || code.length !== 6) {
    showAlert(els.devicesAlert, I18n.t("invalid6DigitCode"));
    return;
  }

  try {
    const codeHash = await CryptoUtils.sha256Hex(code);
    const enc = new TextEncoder();
    if (
      !CryptoUtils.constantTimeCompare(
        enc.encode(codeHash.toLowerCase()),
        enc.encode((req.verification_code_hash || "").toLowerCase())
      )
    ) {
      showAlert(els.devicesAlert, I18n.t("incorrect6DigitCode"));
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

    showAlert(
      els.devicesAlert,
      I18n.t("approvedSuccessAlert", { name: req.new_device_name }),
      "success"
    );
    loadDevicesAndRequests();
  } catch (err) {
    showAlert(els.devicesAlert, I18n.t("approvalFailedAlert", { err: err.message }));
  }
}

// Start Add/Change Phone from New Unverified Phone ONLY
async function startPhoneHandshake(actionType) {
  hideAlert(els.devicesAlert);

  // Guard: never allow an already-verified signed-in device to add itself as a new device
  if (state.currentUser) {
    showAlert(els.devicesAlert, I18n.t("alreadyVerifiedDeviceError"));
    return;
  }

  const targetUsername = els.pairUsername ? els.pairUsername.value.trim() : "";
  const deviceName = els.pairDeviceName ? els.pairDeviceName.value.trim() : "";
  if (!targetUsername || !deviceName) {
    showAlert(els.devicesAlert, I18n.t("pairFieldsRequired"));
    return;
  }

  try {
    const ecdhPair = await CryptoUtils.generateECDHKeyPair();
    const pubBytes = await CryptoUtils.exportECDHPublicKey(ecdhPair.publicKey);

    // Generate unbiased random 6-digit code via rejection sampling
    const maxUnbiased = Math.floor(0x100000000 / 900000) * 900000;
    const randomVals = new Uint32Array(1);
    do {
      crypto.getRandomValues(randomVals);
    } while (randomVals[0] >= maxUnbiased);
    const code = String(100000 + (randomVals[0] % 900000));
    const codeHash = await CryptoUtils.sha256Hex(code);

    const reqRes = await fetch("/api/v1/devices/request", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: targetUsername,
        action_type: actionType,
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
    els.newPhoneStatusText.textContent = I18n.t("newPhoneWaitingStatus");

    // Poll status
    if (state.phonePollTimer) {
      clearInterval(state.phonePollTimer);
    }
    state.phonePollTimer = setInterval(async () => {
      try {
        const stRes = await fetch(
          `/api/v1/devices/requests/${encodeURIComponent(reqData.request_id)}/status`
        );
        const stData = await stRes.json();
        if (stData.status === "approved") {
          clearInterval(state.phonePollTimer);
          state.phonePollTimer = null;
          els.newPhoneStatusText.textContent = I18n.t("newPhoneApprovedStatus");
          await completePhoneHandshake(stData);
        } else if (stData.status === "expired" || stData.status === "rejected") {
          clearInterval(state.phonePollTimer);
          state.phonePollTimer = null;
          els.newPhoneStatusText.textContent = I18n.t("newPhoneStatusPrefix", {
            status: stData.status,
          });
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

    const compRes = await fetch(
      `/api/v1/devices/requests/${encodeURIComponent(state.pendingNewPhoneRequestId)}/complete`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attestation: WebAuthnHelper.serializeCreationResponse(credential),
          wrapped_mek: CryptoUtils.bytesToBase64Url(wrappedMek),
          wrapped_mek_iv: CryptoUtils.bytesToBase64Url(wrappedMekIv),
        }),
      }
    );
    const compData = await compRes.json();
    if (!compRes.ok) throw new Error(compData.message || compData.error);

    if (compData.csrf_token) {
      state.csrfToken = compData.csrf_token;
    }
    if (compData.credential_id) {
      state.activeCredId = compData.credential_id;
    }

    els.newPhoneStatusText.textContent = I18n.t("newPhoneEnrolledStatus");
    setTimeout(async () => {
      els.newPhoneSection.style.display = "none";
      closeDevicesModal();
      await checkAuthStatus();
    }, 1200);
  } catch (err) {
    showAlert(els.devicesAlert, I18n.t("handshakeFailedAlert", { err: err.message }));
  }
}

els.btnAddPhone.addEventListener("click", () => setPairActionMode("add_phone"));
els.btnChangePhone.addEventListener("click", () => setPairActionMode("change_phone"));
if (els.btnStartPairing) {
  els.btnStartPairing.addEventListener("click", () =>
    startPhoneHandshake(state.selectedPairAction || "add_phone")
  );
}

async function revokeDevice(credIdHex, deviceName) {
  if (!confirm(I18n.t("confirmRevokeDevice", { name: deviceName }))) return;
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
    showAlert(els.devicesAlert, I18n.t("deviceRevokedAlert", { name: deviceName }), "info");
    loadDevicesAndRequests();
  } catch (err) {
    showAlert(els.devicesAlert, I18n.t("revokeFailedAlert", { err: err.message }));
  }
}

// Start App
checkSealStatus();
