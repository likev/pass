/**
 * Zero-Knowledge Client-Side TOTP (RFC 6238) & QR Code Scanner Utilities
 * - Parses otpauth://totp/... URIs and Base32 seeds
 * - Decodes QR codes locally via @paulmillr/qr (web/static/js/qr/decode.js & dom.js)
 * - Generates 6-digit (or 8-digit) TOTP codes in RAM via Web Crypto HMAC
 */

import { CryptoUtils } from "./crypto.js";
import decodeQR from "./qr/decode.js";
import { QRCanvas, frontalCamera, frameLoop } from "./qr/dom.js";

export const TOTPUtils = (() => {
    const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let activeCamera = null;
    let activeCanvas = null;
    let cancelLoop = null;
    let isScanning = false;

    /**
     * Decodes RFC 4648 Base32 string into a Uint8Array
     */
    function decodeBase32(input) {
        if (!input || typeof input !== 'string') {
            throw new Error('Empty TOTP secret');
        }
        const cleaned = input.toUpperCase().replace(/[\s\-=]+/g, '');
        if (!cleaned.length) {
            throw new Error('Empty TOTP secret');
        }

        let bits = 0;
        let value = 0;
        const output = new Uint8Array(Math.floor((cleaned.length * 5) / 8));
        let index = 0;

        for (let i = 0; i < cleaned.length; i++) {
            const charIdx = BASE32_ALPHABET.indexOf(cleaned[i]);
            if (charIdx === -1) {
                throw new Error('Invalid Base32 character in TOTP secret');
            }
            value = (value << 5) | charIdx;
            bits += 5;
            if (bits >= 8) {
                output[index++] = (value >>> (bits - 8)) & 0xff;
                bits -= 8;
            }
        }
        return output;
    }

    /**
     * Parses an otpauth://totp/... URI or a raw Base32 secret string.
     * Returns { canonicalUri, suggestedName, digits, period, algorithm }
     */
    function parseTotpInput(rawInput) {
        if (!rawInput || typeof rawInput !== 'string') {
            throw new Error('Please scan a TOTP QR code or enter a setup key');
        }
        const trimmed = rawInput.trim();
        if (!trimmed) {
            throw new Error('Please scan a TOTP QR code or enter a setup key');
        }

        if (trimmed.toLowerCase().startsWith('otpauth://')) {
            let parsedUrl;
            try {
                parsedUrl = new URL(trimmed);
            } catch (e) {
                throw new Error('Invalid otpauth:// URI format');
            }

            const otpType = (parsedUrl.host || parsedUrl.hostname || '').toLowerCase();
            let rawPath = parsedUrl.pathname || '';
            if (!otpType && rawPath.toLowerCase().startsWith('//totp/')) {
                rawPath = rawPath.slice(6);
            } else if (otpType && otpType !== 'totp') {
                throw new Error('Only TOTP (time-based) QR codes are supported');
            }

            const secretParam = parsedUrl.searchParams.get('secret');
            if (!secretParam) {
                throw new Error('QR code is missing the TOTP secret parameter');
            }

            const cleanSecret = secretParam.toUpperCase().replace(/[\s\-=]+/g, '');
            const testBytes = decodeBase32(cleanSecret);
            CryptoUtils.zeroBuffer(testBytes);

            let algorithm = (parsedUrl.searchParams.get('algorithm') || 'SHA1').toUpperCase().replace('-', '');
            if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) {
                algorithm = 'SHA1';
            }

            let digits = parseInt(parsedUrl.searchParams.get('digits') || '6', 10);
            if (![6, 7, 8].includes(digits)) {
                digits = 6;
            }

            let period = parseInt(parsedUrl.searchParams.get('period') || '30', 10);
            if (!Number.isFinite(period) || period <= 0 || period > 300) {
                period = 30;
            }

            const issuerParam = (parsedUrl.searchParams.get('issuer') || '').trim();
            let label = decodeURIComponent(rawPath.replace(/^\/+/, '')).trim();
            let suggestedName = '';

            if (label) {
                if (label.includes(':')) {
                    const parts = label.split(':');
                    const labelIssuer = parts[0].trim();
                    const labelAccount = parts.slice(1).join(':').trim();
                    const finalIssuer = issuerParam || labelIssuer;
                    suggestedName = labelAccount ? `${finalIssuer} (${labelAccount})` : finalIssuer;
                } else if (issuerParam && !label.toLowerCase().startsWith(issuerParam.toLowerCase())) {
                    suggestedName = `${issuerParam} (${label})`;
                } else {
                    suggestedName = label;
                }
            } else if (issuerParam) {
                suggestedName = issuerParam;
            }

            const canonicalLabel = encodeURIComponent(label || issuerParam || 'TOTP');
            const canonicalParams = new URLSearchParams();
            canonicalParams.set('secret', cleanSecret);
            if (issuerParam) canonicalParams.set('issuer', issuerParam);
            canonicalParams.set('algorithm', algorithm);
            canonicalParams.set('digits', String(digits));
            canonicalParams.set('period', String(period));

            return {
                canonicalUri: `otpauth://totp/${canonicalLabel}?${canonicalParams.toString()}`,
                suggestedName,
                digits,
                period,
                algorithm
            };
        }

        // Raw Base32 setup key
        const cleanSecret = trimmed.toUpperCase().replace(/[\s\-=]+/g, '');
        if (cleanSecret.length < 8) {
            throw new Error('TOTP setup key is too short');
        }
        const testBytes = decodeBase32(cleanSecret);
        CryptoUtils.zeroBuffer(testBytes);

        return {
            canonicalUri: `otpauth://totp/Account?secret=${cleanSecret}&algorithm=SHA1&digits=6&period=30`,
            suggestedName: '',
            digits: 6,
            period: 30,
            algorithm: 'SHA1'
        };
    }

    /**
     * Generates a TOTP code from decrypted plaintext bytes (Uint8Array) in memory.
     * Immediately zeroes intermediate secret key material.
     */
    async function generateTotpFromBytes(plaintextBytes, timestampMs = Date.now()) {
        const rawText = new TextDecoder().decode(plaintextBytes);
        const parsed = parseTotpInput(rawText);
        const url = new URL(parsed.canonicalUri);
        const secretBase32 = url.searchParams.get('secret');
        const secretBytes = decodeBase32(secretBase32);

        const counterBuf = new Uint8Array(8);
        try {
            let hashName = 'SHA-1';
            if (parsed.algorithm === 'SHA256') hashName = 'SHA-256';
            else if (parsed.algorithm === 'SHA512') hashName = 'SHA-512';

            const epochSeconds = Math.floor(timestampMs / 1000);
            let counter = Math.floor(epochSeconds / parsed.period);
            for (let i = 7; i >= 0; i--) {
                counterBuf[i] = counter & 0xff;
                counter = Math.floor(counter / 256);
            }

            const hmacKey = await crypto.subtle.importKey(
                'raw',
                secretBytes,
                { name: 'HMAC', hash: { name: hashName } },
                false,
                ['sign']
            );

            const sigBuffer = await crypto.subtle.sign('HMAC', hmacKey, counterBuf);
            const hmac = new Uint8Array(sigBuffer);
            const offset = hmac[hmac.length - 1] & 0x0f;
            const binary =
                ((hmac[offset] & 0x7f) << 24) |
                ((hmac[offset + 1] & 0xff) << 16) |
                ((hmac[offset + 2] & 0xff) << 8) |
                (hmac[offset + 3] & 0xff);

            const mod = Math.pow(10, parsed.digits);
            const code = (binary % mod).toString().padStart(parsed.digits, '0');
            const remainingSeconds = parsed.period - (epochSeconds % parsed.period);

            CryptoUtils.zeroBuffer(hmac);
            return {
                code,
                remainingSeconds,
                period: parsed.period,
                digits: parsed.digits
            };
        } finally {
            CryptoUtils.zeroBuffer(secretBytes);
            CryptoUtils.zeroBuffer(counterBuf);
        }
    }

    /**
     * Decodes a QR code from a Canvas 2D context using @paulmillr/qr
     */
    function decodeQrFromCanvas(canvas, ctx) {
        const width = canvas.width;
        const height = canvas.height;
        if (!width || !height) return null;

        const imageData = ctx.getImageData(0, 0, width, height);
        try {
            const decoded = decodeQR(imageData, { cropToSquare: false });
            if (decoded) return decoded;
        } catch (_) {
            // Try square crop fallback
        }
        try {
            const decoded = decodeQR(imageData, { cropToSquare: true });
            if (decoded) return decoded;
        } catch (_) {
            // Not detected in this frame
        }
        return null;
    }

    /**
     * Decodes a QR code from an uploaded or pasted Image File / Blob using @paulmillr/qr
     */
    async function decodeQrFromFile(file) {
        if (!file) throw new Error('No image file selected');

        const imgUrl = URL.createObjectURL(file);
        try {
            const img = await new Promise((resolve, reject) => {
                const el = new Image();
                el.onload = () => resolve(el);
                el.onerror = () => reject(new Error('Failed to load QR image'));
                el.src = imgUrl;
            });

            const maxDim = 1200;
            let width = img.naturalWidth || img.width;
            let height = img.naturalHeight || img.height;
            if (width > maxDim || height > maxDim) {
                const scale = maxDim / Math.max(width, height);
                width = Math.round(width * scale);
                height = Math.round(height * scale);
            }

            const canvas = document.createElement('canvas');
            canvas.width = width;
            canvas.height = height;
            const ctx = canvas.getContext('2d', { willReadFrequently: true });
            ctx.drawImage(img, 0, 0, width, height);

            const decoded = decodeQrFromCanvas(canvas, ctx);
            if (!decoded) {
                throw new Error('No QR code detected in the image');
            }
            return decoded;
        } finally {
            URL.revokeObjectURL(imgUrl);
        }
    }

    /**
     * Starts live camera QR scanning on the provided <video> element using @paulmillr/qr
     */
    async function startCameraScanner(videoEl, onDetect, onError) {
        stopCameraScanner();

        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            throw new Error('Camera access is not supported in this browser');
        }

        activeCanvas = new QRCanvas({}, { cropToSquare: true });
        activeCamera = await frontalCamera(videoEl);
        isScanning = true;

        cancelLoop = frameLoop(() => {
            if (!isScanning || !activeCamera || !activeCanvas) return;
            try {
                if (videoEl.readyState >= HTMLMediaElement.HAVE_ENOUGH_DATA && videoEl.videoWidth > 0) {
                    const result = activeCamera.readFrame(activeCanvas, true);
                    if (result && isScanning) {
                        stopCameraScanner();
                        onDetect(result);
                    }
                }
            } catch (err) {
                if (onError) onError(err);
            }
        });
    }

    /**
     * Stops active camera QR stream
     */
    function stopCameraScanner() {
        isScanning = false;
        if (cancelLoop) {
            cancelLoop();
            cancelLoop = null;
        }
        if (activeCamera) {
            activeCamera.stop();
            activeCamera = null;
        }
        if (activeCanvas) {
            activeCanvas.clear();
            activeCanvas = null;
        }
    }

    return {
        parseTotpInput,
        generateTotpFromBytes,
        decodeQrFromFile,
        startCameraScanner,
        stopCameraScanner,
        isCameraActive: () => isScanning
    };
})();
