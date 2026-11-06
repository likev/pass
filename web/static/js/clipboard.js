/**
 * Web Password & Key Manager - Direct-to-Clipboard & 3-Minute Auto-Clear Guard
 */

export const ClipboardGuard = {
  clearTimer: null,
  updateInterval: null,
  targetTime: 0,
  pendingImmediateClear: false,
  activeReason: null, // "copied" | "pasted" | "generated"
  onTickCallback: null,
  onClearCallback: null,

  init(onTick, onClear) {
    this.onTickCallback = onTick;
    this.onClearCallback = onClear;

    // Background tab focus recovery handlers
    const handleRefocus = async () => {
      if (this.pendingImmediateClear || (this.targetTime > 0 && Date.now() >= this.targetTime)) {
        await this.clearNow();
      }
    };

    window.addEventListener("focus", handleRefocus);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) {
        handleRefocus();
      }
    });
    window.addEventListener("pointerdown", handleRefocus, { capture: true });
    window.addEventListener("keydown", handleRefocus, { capture: true });

    // Best-effort clear on page exit
    window.addEventListener("pagehide", () => this.clearNow());
    window.addEventListener("beforeunload", () => this.clearNow());
  },

  scheduleClear(durationMs = 180000, reason = "copied") {
    this.cancelPendingTimer();
    this.activeReason = reason;
    this.targetTime = Date.now() + durationMs;
    this.pendingImmediateClear = false;

    // Tick every 500ms to update visible countdown
    this.updateInterval = setInterval(() => {
      const remainingMs = Math.max(0, this.targetTime - Date.now());
      if (this.onTickCallback) {
        this.onTickCallback(remainingMs, this.activeReason, this.pendingImmediateClear);
      }
      if (remainingMs <= 0) {
        this.clearNow();
      }
    }, 500);

    // Initial immediate tick
    if (this.onTickCallback) {
      this.onTickCallback(durationMs, this.activeReason, this.pendingImmediateClear);
    }
  },

  cancelPendingTimer() {
    if (this.clearTimer) {
      clearTimeout(this.clearTimer);
      this.clearTimer = null;
    }
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
    this.targetTime = 0;
    this.activeReason = null;
    if (this.onTickCallback && !this.pendingImmediateClear) {
      this.onTickCallback(0, null, false);
    }
  },

  async clearNow() {
    if (this.clearTimer) {
      clearTimeout(this.clearTimer);
      this.clearTimer = null;
    }
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
    this.targetTime = 0;

    let success = false;

    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText("");
        success = true;
      } else if (navigator.clipboard && navigator.clipboard.write) {
        const item = new ClipboardItem({
          "text/plain": new Blob([""], { type: "text/plain" }),
        });
        await navigator.clipboard.write([item]);
        success = true;
      }
    } catch (err) {
      // Browser rejected background clipboard write (e.g. tab not focused)
      this.pendingImmediateClear = true;
      document.title = "[!] Focus tab to clear clipboard - Key Manager";
      if (this.onTickCallback) {
        this.onTickCallback(0, this.activeReason, true);
      }
    }

    if (success) {
      this.pendingImmediateClear = false;
      this.activeReason = null;
      document.title = "Passkey Web Key Manager";
      if (this.onClearCallback) {
        this.onClearCallback();
      }
    }
  },

  // Write transient byte array directly to system clipboard as text/plain Blob
  async writeBytesDirect(plaintextBytes, reason = "copied") {
    try {
      let written = false;
      if (navigator.clipboard && navigator.clipboard.write) {
        try {
          const blob = new Blob([plaintextBytes], { type: "text/plain" });
          const item = new ClipboardItem({
            "text/plain": blob,
          });
          await navigator.clipboard.write([item]);
          written = true;
        } catch (e) {
          // Fallback to writeText below
        }
      }
      if (!written && navigator.clipboard && navigator.clipboard.writeText) {
        const text = new TextDecoder().decode(plaintextBytes);
        await navigator.clipboard.writeText(text);
        written = true;
      }
      if (!written) {
        throw new Error("Clipboard write permission rejected or not supported");
      }
      // Start 3-minute auto-clear timer
      this.scheduleClear(180 * 1000, reason);
    } finally {
      // Immediately wipe plaintext bytes in caller
      if (plaintextBytes && plaintextBytes.fill) {
        plaintextBytes.fill(0);
      }
    }
  },

  // Allows user click gesture to initiate clipboard write with a pending promise
  // so Safari and Chromium don't drop transient activation during async operations
  async writeViaPromise(blobPromise, reason = "copied") {
    this.cancelPendingTimer();
    try {
      if (typeof ClipboardItem !== "undefined" && navigator.clipboard && navigator.clipboard.write) {
        const item = new ClipboardItem({
          "text/plain": blobPromise,
        });
        await navigator.clipboard.write([item]);
        this.scheduleClear(180 * 1000, reason);
        return true;
      }
    } catch (e) {
      console.warn("ClipboardItem promise write not supported, falling back to direct write:", e);
    }

    const blob = await blobPromise;
    const arrayBuf = await blob.arrayBuffer();
    const bytes = new Uint8Array(arrayBuf);
    await this.writeBytesDirect(bytes, reason);
    return true;
  },
};
