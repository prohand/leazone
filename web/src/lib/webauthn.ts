import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser"
import type { WebAuthnBegin, WebAuthnFinish } from "@/api/types"

/*
 * The server returns WebAuthn options wrapped as { publicKey: ... }
 * (go-webauthn format). We unwrap it for @simplewebauthn/browser and send
 * the resulting JSON back as `credential` together with the ceremonyId.
 */

export const webauthnSupported = () => browserSupportsWebAuthn()

function unwrap<T>(begin: WebAuthnBegin): T {
  const opts = begin.options as unknown as { publicKey?: T } | undefined
  if (!opts?.publicKey) throw new Error("Réponse WebAuthn invalide du serveur.")
  return opts.publicKey
}

// The spec types `credential` as an opaque object.
function finish(begin: WebAuthnBegin, credential: object): WebAuthnFinish {
  return { ceremonyId: begin.ceremonyId ?? "", credential: credential as WebAuthnFinish["credential"] }
}

export async function authenticate(begin: WebAuthnBegin) {
  const credential = await startAuthentication({
    optionsJSON: unwrap<PublicKeyCredentialRequestOptionsJSON>(begin),
  })
  return finish(begin, credential)
}

export async function register(begin: WebAuthnBegin) {
  const credential = await startRegistration({
    optionsJSON: unwrap<PublicKeyCredentialCreationOptionsJSON>(begin),
  })
  return finish(begin, credential)
}

/** Default passkey name from the platform, e.g. "Passkey macOS". */
export function defaultPasskeyName(): string {
  const ua = navigator.userAgent
  const os = /iPhone|iPad/.test(ua)
    ? "iPhone"
    : /Android/.test(ua)
      ? "Android"
      : /Mac OS X/.test(ua)
        ? "Mac"
        : /Windows/.test(ua)
          ? "Windows"
          : /Linux/.test(ua)
            ? "Linux"
            : "appareil"
  return `Passkey ${os}`
}
