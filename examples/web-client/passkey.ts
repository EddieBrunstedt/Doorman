// Passkey registration and authentication helpers for a frontend talking
// to the bauth-axum endpoints. The only non-obvious work is converting
// between the base64url strings the server sends and the ArrayBuffers
// the WebAuthn DOM APIs require.

function base64UrlToBuffer(input: string): ArrayBuffer {
  const padded = input.padEnd(input.length + ((4 - (input.length % 4)) % 4), "=");
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function bufferToBase64Url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

type ServerCreationOptions = {
  publicKey: {
    challenge: string;
    user: { id: string; name: string; displayName: string };
    rp: { id: string; name: string };
    pubKeyCredParams: Array<{ type: "public-key"; alg: number }>;
    timeout?: number;
    attestation?: AttestationConveyancePreference;
    excludeCredentials?: Array<{ type: "public-key"; id: string; transports?: AuthenticatorTransport[] }>;
    authenticatorSelection?: AuthenticatorSelectionCriteria;
    extensions?: AuthenticationExtensionsClientInputs;
  };
};

type ServerRequestOptions = {
  publicKey: {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: Array<{ type: "public-key"; id: string; transports?: AuthenticatorTransport[] }>;
    userVerification?: UserVerificationRequirement;
    extensions?: AuthenticationExtensionsClientInputs;
  };
};

function decodeCreationOptions(o: ServerCreationOptions): CredentialCreationOptions {
  const p = o.publicKey;
  return {
    publicKey: {
      ...p,
      challenge: base64UrlToBuffer(p.challenge),
      user: { ...p.user, id: base64UrlToBuffer(p.user.id) },
      excludeCredentials: p.excludeCredentials?.map((c) => ({
        ...c,
        id: base64UrlToBuffer(c.id),
      })),
    },
  };
}

function decodeRequestOptions(o: ServerRequestOptions): CredentialRequestOptions {
  const p = o.publicKey;
  return {
    publicKey: {
      ...p,
      challenge: base64UrlToBuffer(p.challenge),
      allowCredentials: p.allowCredentials?.map((c) => ({
        ...c,
        id: base64UrlToBuffer(c.id),
      })),
    },
  };
}

function encodeAttestation(cred: PublicKeyCredential) {
  const att = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufferToBase64Url(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bufferToBase64Url(att.attestationObject),
      clientDataJSON: bufferToBase64Url(att.clientDataJSON),
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

function encodeAssertion(cred: PublicKeyCredential) {
  const a = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufferToBase64Url(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bufferToBase64Url(a.authenticatorData),
      clientDataJSON: bufferToBase64Url(a.clientDataJSON),
      signature: bufferToBase64Url(a.signature),
      userHandle: a.userHandle ? bufferToBase64Url(a.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${path} -> ${res.status} ${await res.text()}`);
  return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
}

export async function registerPasskey(name?: string): Promise<void> {
  const start = await postJson<{ challengeId: string; options: ServerCreationOptions }>(
    "/auth/passkey/register/start",
    {},
  );
  const cred = (await navigator.credentials.create(
    decodeCreationOptions(start.options),
  )) as PublicKeyCredential | null;
  if (!cred) throw new Error("user cancelled passkey registration");
  await postJson("/auth/passkey/register/finish", {
    challengeId: start.challengeId,
    response: encodeAttestation(cred),
    name,
  });
}

export async function authenticatePasskey(email: string): Promise<void> {
  const start = await postJson<{ challengeId: string; options: ServerRequestOptions }>(
    "/auth/passkey/authenticate/start",
    { email },
  );
  const cred = (await navigator.credentials.get(
    decodeRequestOptions(start.options),
  )) as PublicKeyCredential | null;
  if (!cred) throw new Error("user cancelled passkey authentication");
  await postJson("/auth/passkey/authenticate/finish", {
    challengeId: start.challengeId,
    response: encodeAssertion(cred),
  });
}
