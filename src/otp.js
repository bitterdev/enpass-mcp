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

// True when a field value looks like a time-based OTP secret.
export function isOtpValue(value) {
  return typeof value === "string" && value.trim().toLowerCase().startsWith("otpauth://");
}
