/**
 * Web Password & Key Manager - Internationalization (en / zh)
 */

const translations = {
  en: {
    pageTitle: "Passkey Web Key Manager",
    brandTitle: "Web Key Manager",
    badgeZeroKnowledge: "E2EE Zero-Knowledge",
    btnDevices: "Devices",
    btnSignOut: "Sign Out",
    btnClearClipboardNow: "Clear Now",

    // Clipboard Banner
    clipboardPendingWipe: "⚠️ Background clipboard wipe pending — focus tab or click to clear!",
    clipboardPastedLabel: "Pasted secret in clipboard",
    clipboardCopiedLabel: "Decrypted key in clipboard",
    clipboardCountdown: "{label} — auto-clearing in {time}",
    clipboardAutoCleared: "Clipboard securely auto-cleared.",

    // Unseal View
    unsealInitTitle: "First-Time Server Initialization",
    unsealInitDesc: "Set a strong Admin Startup Passphrase (min 12 chars). This seals the Server Master Key (SMK) via Argon2id + AES-256-GCM.",
    unsealInitBtn: "Initialize & Unseal Server",
    unsealSealedTitle: "Server Sealed",
    unsealSealedDesc: "Enter the Admin Startup Passphrase to unseal the Server Master Key into mlock RAM.",
    unsealSealedBtn: "Unseal Server",
    unsealPassLabel: "Admin Startup Passphrase (min 12 chars)",
    unsealPassConfirmLabel: "Confirm Admin Startup Passphrase",
    unsealMinLenError: "Passphrase must be at least 12 characters.",
    unsealMismatchError: "Passphrases do not match.",
    unsealConnectError: "Failed to connect to backend server: {err}",

    // Auth View
    authTitle: "Passkey Authentication",
    authSubtitle: "Zero master passwords. Hardware-backed WebAuthn passkeys with client-side PRF envelope encryption.",
    loginHeading: "Sign In",
    loginDesc: "Authenticate with an existing passkey on this device.",
    loginUsernameLabel: "Username *",
    loginUsernamePlaceholder: "alice",
    loginUsernameRequired: "Username is required to sign in.",
    btnLogin: "Sign In with Passkey",
    btnConnectOrReplacePhone: "Connect or Replace Phone",
    authDivider: "OR",
    registerHeading: "Register First Device",
    registerDesc: "Create a new account and bind your primary hardware passkey.",
    regUsernameLabel: "Username *",
    regUsernamePlaceholder: "alice",
    regDisplayNameLabel: "Display Name",
    regDisplayNamePlaceholder: "Alice Smith",
    regDeviceNameLabel: "Device Name",
    regDeviceNamePlaceholder: "MacBook Pro / iPhone 16 / Pixel 9",
    btnRegister: "Create Passkey & Register",
    regUsernameRequired: "Username is required for registration.",
    regFailed: "Registration failed: {err}",
    loginFailed: "Login failed: {err}",
    defaultDeviceName: "My Device",

    // Single-Device Risk Banner
    singleDeviceTitle: "Single-Device Data Loss Risk",
    singleDeviceDesc: "You only have 1 verified device enrolled. Because your keys are encrypted with your hardware Passkey, all data will be permanently lost if this phone or device is broken, lost, or stolen.",
    btnAddBackupDevice: "+ Add Backup Device",

    // Dashboard View
    keysFilterPlaceholder: "Filter keys & 2FA TOTP by name (metadata only)...",
    filterTypeAll: "All",
    filterTypeSecret: "Keys",
    filterTypeTotp: "2FA TOTP",
    badgeTotp: "2FA TOTP",
    btnCreateNewKey: "+ Create New Key",
    storedKeysTitle: "Stored Keys",
    storedKeysSubtitle: "Each key retrieval requires live hardware Passkey verification",
    emptyKeysList: "No keys found. Click \"+ Create New Key\" to encrypt and store your first key or 2FA TOTP.",
    keyUpdatedPrefix: "Updated: {date}",
    btnCopyKey: "Copy Key",
    btnCopyTotp: "🔢 Copy 6-Digit Code",
    btnDeleteKey: "Delete",
    keyCopiedAlert: "Key \"{name}\" decrypted directly to clipboard! (Auto-clears in 3 minutes)",
    totpCopiedAlert: "6-digit 2FA code for \"{name}\" copied to clipboard! (Valid for {sec}s)",
    keyCopyFailed: "Failed to retrieve/decrypt key: {err}",
    confirmDeleteKey: "Are you sure you want to permanently delete \"{name}\"? Passkey verification is required.",
    keyDeletedAlert: "Key \"{name}\" deleted.",
    keyDeleteFailed: "Delete failed: {err}",
    loadKeysFailed: "Failed to load keys: {err}",

    // Create Key Modal
    modalCreateKeyTitle: "Create New Key",
    keyNameLabel: "Key Name (e.g. prod-aws-secret, github-pat) *",
    keyNamePlaceholder: "my-service-key",
    tabType: "1. Type Manually",
    tabPaste: "2. Paste Key",
    tabGen: "3. Auto-Generate",
    tabTotp: "4. TOTP / 2FA QR",
    modeTypeHint: "Secrets are never shown in plaintext. Type your secret twice to verify a byte-for-byte match.",
    keyTypePrimaryLabel: "Enter Secret Key *",
    keyTypeConfirmLabel: "Confirm Secret Key (paste disabled) *",
    modePasteHint: "Read directly from your system clipboard into ephemeral RAM. Plaintext is never rendered in the DOM.",
    btnPasteCapture: "Paste from Clipboard",
    pasteStatusEmpty: "No pasted key captured yet.",
    pasteStatusCaptured: "Captured in memory ({bytes} bytes) — ready to encrypt",
    modePasteNote: "Pasting automatically starts the 3-minute clipboard auto-clear timer to wipe the secret from your OS clipboard.",
    modeGenHint: "Generate unbiased high-entropy secrets in memory via CSPRNG rejection sampling. Never rendered in the DOM.",
    genPresetLabel: "Format Preset",
    genPresetPassword: "Random Password (A-Z, a-z, 0-9, Symbols)",
    genPresetHex: "Hex Key (256-bit / 64 hex chars)",
    genPresetBase64Url: "Base64URL Secret (256-bit)",
    genLengthLabelPrefix: "Length:",
    genLengthLabelSuffix: "characters",
    genCopyCheckboxLabel: "Also copy generated key to clipboard (auto-clears in 3 minutes)",
    modeTotpHint: "Scan a 2FA QR code with your camera, upload/paste a QR screenshot, or enter a Base32 setup key. The TOTP seed is E2EE encrypted and generates 6-digit codes on demand.",
    btnTotpScanCamera: "Scan QR with Camera",
    btnTotpStopCamera: "Stop Camera",
    btnTotpUploadQr: "Upload QR Image",
    totpCameraAimHint: "Point camera at 2FA QR code...",
    totpStatusEmpty: "No TOTP seed captured yet.",
    totpStatusCaptured: "✓ 2FA TOTP seed captured ({digits} digits, {period}s) — ready to encrypt",
    totpManualLabel: "Or Enter Setup Key (Base32) / otpauth:// URI",
    totpManualPlaceholder: "JBSWY3DPEHPK3PXP or otpauth://totp/...",
    totpQrScanSuccess: "QR code scanned successfully!",
    totpSavedAlert: "2FA TOTP \"{name}\" encrypted and saved!",
    btnSaveKey: "Encrypt & Save with Passkey",
    pasteDisabledConfirmAlert: "Pasting into the confirmation field is disabled. Please type to confirm.",
    keyExceedsLimitAlert: "Key size exceeds 10KB ({max} bytes) limit.",
    clipboardReadDeniedAlert: "Clipboard read permission denied. Press Ctrl+V / Cmd+V in this window instead.",
    keyNameRequiredAlert: "Please provide a Key Name.",
    keyEnterRequiredAlert: "Please enter the secret key.",
    keyMismatchAlert: "Key confirmation does not match. Please re-enter.",
    noPasteCapturedAlert: "No pasted key captured. Click \"Paste from Clipboard\" or press Ctrl+V / Cmd+V first.",
    invalidGenLengthAlert: "Invalid key length.",
    emptyPayloadAlert: "Key payload is empty.",
    keySavedAlert: "Key \"{name}\" encrypted and saved!",
    keySaveFailedAlert: "Failed to save key: {err}",

    // Devices Modal
    modalDevicesTitle: "Verified Devices & Phone Pairing",
    modalDevicesSubtitle: "Enroll a secondary phone or computer so you never lose access if a device is broken or stolen.",
    modalPairNewDeviceTitle: "Connect or Replace Phone / Device",
    modalPairNewDeviceSubtitle: "Initiate pairing from this new unverified device, then approve it on your existing verified device.",
    verifiedGuideTitle: "How to Add or Replace a Device",
    verifiedGuideStep1: "1. Open this website on your NEW phone or computer (do not sign in; click \"Connect or Replace Phone\" on the Sign-In screen).",
    verifiedGuideStep2: "2. Enter your username on the new device to generate a 6-digit pairing code.",
    verifiedGuideStep3: "3. The request will appear automatically below under \"Pending Approval Requests\" — enter the 6-digit code here to approve.",
    verifiedGuideNote: "Note: This current device is already verified and acts as the Approver. You cannot add this same device again.",
    btnRefreshRequests: "Refresh",
    pairUsernameLabel: "Your Account Username *",
    pairUsernamePlaceholder: "alice",
    pairDeviceNameLabel: "Name for This New Device *",
    pairDeviceNamePlaceholder: "iPhone 16 / Pixel 9 / Backup Laptop",
    pairActionLabel: "Pairing Mode",
    btnAddPhone: "Add as Backup Device",
    btnChangePhone: "Replace Old Phone",
    btnStartPairingCode: "Generate 6-Digit Pairing Code",
    pairFieldsRequired: "Please enter both your account username and a name for this new device.",
    alreadyVerifiedDeviceError: "This device is already verified and signed in. Please open this page on your new unverified device to pair it.",
    newPhonePairingTitle: "New Device Pairing Code",
    newPhonePairingHint: "On your already-verified device, open \"Devices\" and enter this 6-digit code under Pending Approval Requests:",
    newPhoneWaitingStatus: "Waiting for approval on your verified device...",
    newPhoneApprovedStatus: "Approved! Creating Passkey and completing encrypted key transfer...",
    newPhoneEnrolledStatus: "Successfully enrolled and verified this device!",
    newPhoneStatusPrefix: "Request {status}.",
    pendingRequestsHeading: "Pending Approval Requests",
    enrolledDevicesHeading: "Enrolled Devices",
    unauthDevicesNote: "Sign in or complete pairing above to view enrolled devices.",
    unauthPendingNote: "Sign in on an already-verified device to approve pending requests.",
    noPendingRequests: "No pending device requests. Waiting for a new device to request pairing...",
    enrolledDatePrefix: "Enrolled: {date}",
    deviceCurrentBadge: "Current Device",
    statusVerified: "verified",
    statusRevoked: "revoked",
    btnRevoke: "Revoke",
    wantsToConnectAdd: "wants to connect (Add Device)",
    wantsToConnectReplace: "wants to connect (Replace This Device)",
    expiresIn5Min: "Expires in 5 minutes",
    inputCodePlaceholder: "6-digit code",
    btnVerifyApprove: "Verify & Approve",
    invalid6DigitCode: "Please enter the exact 6-digit code shown on the new device.",
    incorrect6DigitCode: "Incorrect 6-digit verification code. Please check the new device's screen.",
    approvedSuccessAlert: "Successfully approved {name}!",
    approvalFailedAlert: "Approval failed: {err}",
    handshakeFailedAlert: "Handshake completion failed: {err}",
    confirmRevokeDevice: "Revoke device \"{name}\"? Passkey verification is required.",
    deviceRevokedAlert: "Device \"{name}\" revoked.",
    revokeFailedAlert: "Revoke failed: {err}",
  },

  zh: {
    pageTitle: "通行密钥管理器 (Web Key Manager)",
    brandTitle: "密钥管理器",
    badgeZeroKnowledge: "端到端零知识加密",
    btnDevices: "设备管理",
    btnSignOut: "退出登录",
    btnClearClipboardNow: "立即清空",

    // Clipboard Banner
    clipboardPendingWipe: "⚠️ 剪贴板待自动清理 — 请点击此处或切换回本页以立即清空！",
    clipboardPastedLabel: "剪贴板中存在已粘贴的密钥",
    clipboardCopiedLabel: "剪贴板中存在已解密的密钥",
    clipboardCountdown: "{label} — 将在 {time} 后自动清空",
    clipboardAutoCleared: "系统剪贴板已安全自动清空。",

    // Unseal View
    unsealInitTitle: "服务器首次初始化",
    unsealInitDesc: "请设置高强度管理员启动口令（至少 12 位）。服务器主密钥 (SMK) 将通过 Argon2id + AES-256-GCM 密封保存。",
    unsealInitBtn: "初始化并解封服务器",
    unsealSealedTitle: "服务器已密封",
    unsealSealedDesc: "请输入管理员启动口令，将服务器主密钥 (SMK) 解封至受保护内存 (mlock RAM)。",
    unsealSealedBtn: "解封服务器",
    unsealPassLabel: "管理员启动口令（至少 12 个字符）",
    unsealPassConfirmLabel: "确认管理员启动口令",
    unsealMinLenError: "启动口令长度至少需要 12 个字符。",
    unsealMismatchError: "两次输入的口令不一致。",
    unsealConnectError: "无法连接到后端服务器：{err}",

    // Auth View
    authTitle: "Passkey 通行密钥认证",
    authSubtitle: "无主密码设计，基于硬件 WebAuthn 通行密钥与客户端 PRF 信封加密保护您的密钥资产。",
    loginHeading: "通行密钥登录",
    loginDesc: "使用当前设备上已绑定的通行密钥直接登录。",
    loginUsernameLabel: "用户名 *",
    loginUsernamePlaceholder: "例如：alice",
    loginUsernameRequired: "登录时必须填写用户名。",
    btnLogin: "使用 Passkey 登录",
    btnConnectOrReplacePhone: "连接新手机 / 更换旧手机",
    authDivider: "或",
    registerHeading: "注册首台设备",
    registerDesc: "创建新账号并绑定您的第一台受信任硬件设备。",
    regUsernameLabel: "用户名 *",
    regUsernamePlaceholder: "例如：alice",
    regDisplayNameLabel: "显示名称",
    regDisplayNamePlaceholder: "例如：Alice",
    regDeviceNameLabel: "当前设备名称",
    regDeviceNamePlaceholder: "例如：MacBook Pro / iPhone 16 / Pixel 9",
    btnRegister: "创建通行密钥并注册",
    regUsernameRequired: "注册时必须填写用户名。",
    regFailed: "注册失败：{err}",
    loginFailed: "登录失败：{err}",
    defaultDeviceName: "我的设备",

    // Single-Device Risk Banner
    singleDeviceTitle: "单设备数据丢失风险提示",
    singleDeviceDesc: "您当前仅绑定了 1 台受信任设备。由于密钥采用端到端硬件通行密钥加密，一旦此手机或设备损坏、遗失或被盗，所有密钥数据将永久无法恢复！建议立即添加一台备用设备。",
    btnAddBackupDevice: "+ 添加备用设备",

    // Dashboard View
    keysFilterPlaceholder: "按名称搜索密钥或 2FA 验证码（仅检索元数据）...",
    filterTypeAll: "全部",
    filterTypeSecret: "普通密钥",
    filterTypeTotp: "2FA 验证码",
    badgeTotp: "2FA 验证码",
    btnCreateNewKey: "+ 新建密钥",
    storedKeysTitle: "已存储的密钥",
    storedKeysSubtitle: "每次提取单个密钥或 6 位验证码均需通过硬件 Passkey 验证",
    emptyKeysList: "暂无密钥。点击右上角「+ 新建密钥」加密保存您的第一个密钥或 2FA 验证码。",
    keyUpdatedPrefix: "更新于：{date}",
    btnCopyKey: "复制密钥",
    btnCopyTotp: "🔢 复制 6 位验证码",
    btnDeleteKey: "删除",
    keyCopiedAlert: "密钥「{name}」已解密并复制到剪贴板！（3 分钟后自动清空）",
    totpCopiedAlert: "「{name}」的 6 位动态验证码已复制到剪贴板！（剩余有效期 {sec} 秒）",
    keyCopyFailed: "提取或解密密钥失败：{err}",
    confirmDeleteKey: "确定要永久删除密钥「{name}」吗？此操作需要验证通行密钥。",
    keyDeletedAlert: "密钥「{name}」已删除。",
    keyDeleteFailed: "删除失败：{err}",
    loadKeysFailed: "加载密钥列表失败：{err}",

    // Create Key Modal
    modalCreateKeyTitle: "新建加密密钥",
    keyNameLabel: "密钥名称（如 prod-aws-secret、github-2fa）*",
    keyNamePlaceholder: "my-service-key",
    tabType: "1. 手动输入",
    tabPaste: "2. 剪贴板粘贴",
    tabGen: "3. 随机生成",
    tabTotp: "4. TOTP 二维码",
    modeTypeHint: "为确保零泄露，密钥明文绝不在屏幕上显示。请手动输入两次以进行逐字节比对校验。",
    keyTypePrimaryLabel: "输入密钥 *",
    keyTypeConfirmLabel: "再次输入确认密钥（已禁用粘贴）*",
    modePasteHint: "直接从系统剪贴板读取至临时内存，明文绝不写入页面 DOM。",
    btnPasteCapture: "从剪贴板读取",
    pasteStatusEmpty: "尚未捕获剪贴板密钥",
    pasteStatusCaptured: "已在内存中捕获（{bytes} 字节）— 可立即加密",
    modePasteNote: "粘贴后将自动启动 3 分钟剪贴板倒计时，到期自动清空系统剪贴板中的残留明文。",
    modeGenHint: "在内存中通过 CSPRNG 拒绝采样生成无偏高熵密钥，明文绝不渲染至页面 DOM。",
    genPresetLabel: "生成格式",
    genPresetPassword: "高强度随机密码（大小写字母 + 数字 + 符号）",
    genPresetHex: "十六进制密钥（256 位 / 64 个十六进制字符）",
    genPresetBase64Url: "Base64URL 密钥（256 位）",
    genLengthLabelPrefix: "长度：",
    genLengthLabelSuffix: "个字符",
    genCopyCheckboxLabel: "保存后同时复制生成的密钥到剪贴板（3 分钟后自动清空）",
    modeTotpHint: "使用摄像头扫描 2FA 二维码、上传/粘贴二维码截图，或输入 Base32 密钥种子。种子将端到端加密存储，按需计算并复制 6 位验证码。",
    btnTotpScanCamera: "摄像头扫码",
    btnTotpStopCamera: "关闭摄像头",
    btnTotpUploadQr: "上传二维码图片",
    totpCameraAimHint: "请将摄像头对准 2FA 二维码...",
    totpStatusEmpty: "尚未捕获 TOTP 密钥种子",
    totpStatusCaptured: "✓ 已在内存中捕获 2FA 种子（{digits} 位，{period} 秒周期）— 可立即加密",
    totpManualLabel: "或手动输入 Base32 密钥种子 / otpauth:// 链接",
    totpManualPlaceholder: "JBSWY3DPEHPK3PXP 或 otpauth://totp/...",
    totpQrScanSuccess: "成功识别 2FA 二维码！",
    totpSavedAlert: "2FA 动态验证码「{name}」已加密保存！",
    btnSaveKey: "使用通行密钥加密并保存",
    pasteDisabledConfirmAlert: "确认框已禁用粘贴，请手动输入第二次以核对密钥。",
    keyExceedsLimitAlert: "密钥大小超过 10KB（{max} 字节）上限。",
    clipboardReadDeniedAlert: "浏览器未授予剪贴板读取权限，请直接在此窗口按 Ctrl+V / Cmd+V 粘贴。",
    keyNameRequiredAlert: "请填写密钥名称。",
    keyEnterRequiredAlert: "请输入密钥内容。",
    keyMismatchAlert: "两次输入的密钥不一致，请重新输入。",
    noPasteCapturedAlert: "尚未捕获粘贴内容，请先点击「从剪贴板读取」或按 Ctrl+V / Cmd+V。",
    invalidGenLengthAlert: "无效的密钥长度。",
    emptyPayloadAlert: "密钥内容为空。",
    keySavedAlert: "密钥「{name}」已加密保存！",
    keySaveFailedAlert: "保存密钥失败：{err}",

    // Devices Modal
    modalDevicesTitle: "受信任设备管理与配对批准",
    modalDevicesSubtitle: "建议绑定备用手机或电脑，防止单台设备损坏或遗失导致加密数据永久丢失。",
    modalPairNewDeviceTitle: "连接新手机 / 更换旧手机",
    modalPairNewDeviceSubtitle: "请在这台尚未绑定的新设备上发起配对请求，然后在已绑定的旧设备上输入配对码进行批准。",
    verifiedGuideTitle: "如何添加备用设备或更换手机",
    verifiedGuideStep1: "1. 在您的【新手机或新电脑】上打开本网站（无需登录，直接点击登录页上的「连接新手机 / 更换旧手机」）。",
    verifiedGuideStep2: "2. 在新设备上输入您的用户名与新设备名称，生成 6 位数字配对码。",
    verifiedGuideStep3: "3. 配对请求将自动显示在下方「待批准的配对请求」中，在此输入新设备上的 6 位配对码即可完成授权。",
    verifiedGuideNote: "提示：当前设备已是受信任设备（作为批准端），不能将当前设备自身重复添加为新设备。",
    btnRefreshRequests: "刷新列表",
    pairUsernameLabel: "您的账号用户名 *",
    pairUsernamePlaceholder: "例如：alice",
    pairDeviceNameLabel: "此新设备的名称 *",
    pairDeviceNamePlaceholder: "例如：iPhone 16 / Pixel 9 / 备用电脑",
    pairActionLabel: "配对方式",
    btnAddPhone: "添加为备用设备",
    btnChangePhone: "替换旧手机",
    btnStartPairingCode: "生成 6 位配对码",
    pairFieldsRequired: "请填写您的账号用户名以及此新设备的名称。",
    alreadyVerifiedDeviceError: "当前设备已是受信任的已登录设备，请勿将当前设备重复添加为新设备。请在您的新设备上发起配对。",
    newPhonePairingTitle: "新设备 6 位配对码",
    newPhonePairingHint: "请在您已认证的旧设备上打开「设备管理」，在「待批准的配对请求」中输入以下 6 位配对码：",
    newPhoneWaitingStatus: "正在等待已认证设备批准...",
    newPhoneApprovedStatus: "已批准！正在创建通行密钥并完成端到端密钥传输...",
    newPhoneEnrolledStatus: "新设备绑定并验证成功！",
    newPhoneStatusPrefix: "配对请求状态：{status}。",
    pendingRequestsHeading: "待批准的配对请求",
    enrolledDevicesHeading: "已绑定的设备",
    unauthDevicesNote: "请先登录或在上方发起配对以查看已绑定设备。",
    unauthPendingNote: "请在已绑定的设备上登录以批准新设备配对请求。",
    noPendingRequests: "暂无待批准的设备配对请求，正在等待新设备发起连接...",
    enrolledDatePrefix: "绑定时间：{date}",
    deviceCurrentBadge: "当前设备",
    statusVerified: "已验证",
    statusRevoked: "已吊销",
    btnRevoke: "吊销",
    wantsToConnectAdd: "请求连接（添加备用设备）",
    wantsToConnectReplace: "请求连接（替换当前旧设备）",
    expiresIn5Min: "5 分钟内有效",
    inputCodePlaceholder: "输入 6 位配对码",
    btnVerifyApprove: "验证并批准",
    invalid6DigitCode: "请输入新设备屏幕上显示的完整 6 位数字配对码。",
    incorrect6DigitCode: "6 位验证码不正确，请核对新设备屏幕上的数字。",
    approvedSuccessAlert: "已成功批准设备「{name}」！",
    approvalFailedAlert: "批准失败：{err}",
    handshakeFailedAlert: "设备配对完成步骤失败：{err}",
    confirmRevokeDevice: "确定要吊销设备「{name}」吗？此操作需要验证通行密钥。",
    deviceRevokedAlert: "设备「{name}」已吊销。",
    revokeFailedAlert: "吊销设备失败：{err}",
  },
};

const STORAGE_KEY = "passmgr_lang";

function detectInitialLanguage() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "en" || saved === "zh") {
      return saved;
    }
  } catch (_) {}

  const navLangs =
    typeof navigator !== "undefined"
      ? navigator.languages && navigator.languages.length
        ? navigator.languages
        : [navigator.language || "en"]
      : ["en"];

  for (const lang of navLangs) {
    if (typeof lang === "string" && lang.toLowerCase().startsWith("zh")) {
      return "zh";
    }
  }
  return "en";
}

export const I18n = {
  lang: detectInitialLanguage(),
  listeners: [],

  t(key, params = {}) {
    const dict = translations[this.lang] || translations.en;
    let str = dict[key] !== undefined ? dict[key] : translations.en[key] || key;
    for (const [k, v] of Object.entries(params)) {
      str = str.replaceAll(`{${k}}`, String(v));
    }
    return str;
  },

  setLang(newLang) {
    if (newLang !== "en" && newLang !== "zh") return;
    this.lang = newLang;
    try {
      localStorage.setItem(STORAGE_KEY, newLang);
    } catch (_) {}
    this.applyDOMTranslations();
    for (const fn of this.listeners) {
      fn(newLang);
    }
  },

  toggleLang() {
    this.setLang(this.lang === "en" ? "zh" : "en");
  },

  onChange(fn) {
    this.listeners.push(fn);
  },

  applyDOMTranslations() {
    document.documentElement.lang = this.lang === "zh" ? "zh-CN" : "en";
    document.title = this.t("pageTitle");

    document.querySelectorAll("[data-i18n]").forEach((el) => {
      const key = el.getAttribute("data-i18n");
      if (key) {
        el.textContent = this.t(key);
      }
    });

    document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
      const key = el.getAttribute("data-i18n-placeholder");
      if (key) {
        el.setAttribute("placeholder", this.t(key));
      }
    });

    document.querySelectorAll("[data-i18n-title]").forEach((el) => {
      const key = el.getAttribute("data-i18n-title");
      if (key) {
        el.setAttribute("title", this.t(key));
      }
    });
  },
};
