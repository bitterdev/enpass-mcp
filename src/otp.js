/* Author: Fabian Bitter (fabian@bitter.de) */

import * as OTPAuth from "otpauth";

// Generates the current TOTP (RFC 6238) one-time code from a stored secret, which
// Enpass keeps either as an "otpauth://" URI or as a bare base32 secret. Returns
// null for anything that is not a usable time-based secret (e.g. HOTP). The
// timestamp (ms) is injectable for deterministic tests.
export function computeOtp(value, timestamp) {
  if (!value || typeof value !== "string") return null;

  let totp;
  try {
    if (value.trim().toLowerCase().startsWith("otpauth://")) {
      const parsed = OTPAuth.URI.parse(value.trim());
      if (!(parsed instanceof OTPAuth.TOTP)) return null;
      totp = parsed;
    } else {
      const secret = OTPAuth.Secret.fromBase32(value.replace(/\s+/g, "").toUpperCase());
      totp = new OTPAuth.TOTP({ secret });
    }
  } catch {
    return null;
  }

  const ts = typeof timestamp === "number" ? timestamp : Date.now();
  const period = totp.period || 30;
  return {
    code: totp.generate({ timestamp: ts }),
    period,
    secondsRemaining: period - (Math.floor(ts / 1000) % period),
    digits: totp.digits,
    algorithm: totp.algorithm,
  };
}

// Turns a TOTP secret into the form the Enpass app writes into its built-in one-time code
// field: the bare base32 secret, upper case, without spaces. Only that field (type "totp")
// is rendered as a live code; a custom password field holding the same secret is not.
// An otpauth URI with non-default parameters is kept as a URI so nothing is lost.
export function totpFieldValue(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return "";
  if (raw.toLowerCase().startsWith("otpauth://")) {
    const parsed = OTPAuth.URI.parse(raw);
    if (!(parsed instanceof OTPAuth.TOTP)) throw new Error("only time-based (TOTP) secrets are supported");
    const standard = parsed.algorithm === "SHA1" && parsed.digits === 6 && parsed.period === 30;
    return standard ? parsed.secret.base32 : raw;
  }
  const secret = raw.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z2-7]+=*$/.test(secret)) throw new Error("TOTP secret is neither base32 nor an otpauth URI");
  return secret;
}

// True when a custom field looks like it was meant to be the one-time code field.
export function isTotpLikeField({ label = "", value = "" } = {}) {
  return /\b(totp|otp|2fa|einmalcode)\b/i.test(String(label)) || isOtpValue(String(value));
}

// True when a field value looks like a time-based OTP secret.
export function isOtpValue(value) {
  return typeof value === "string" && value.trim().toLowerCase().startsWith("otpauth://");
}
