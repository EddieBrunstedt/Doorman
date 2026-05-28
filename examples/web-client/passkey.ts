// Browser helpers for the bauth-axum passkey-only HTTP surface.
//
// The server serializes WebAuthn options and responses as base64url JSON.
// The browser APIs require ArrayBuffer fields, so these helpers translate
// challenge/user/credential IDs in both directions and then call the bauth
// endpoints for signup, sign-in, recovery, passkey management, and sessions.

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

type Challenge<T> = { challenge_id: string; options: T };

export type UserDto = {
  id: string;
  email: string | null;
  email_verified: boolean;
  created_at: string;
  passkey_count: number;
};

export type SessionDto = {
  id: string;
  created_at: string;
  expires_at: string;
  ip: string | null;
  user_agent: string | null;
  is_current: boolean;
};

export type AuthResponse = {
  user: UserDto;
  session: SessionDto;
  token: string;
};

export type PasskeyDto = {
  credential_id: string;
  name: string | null;
  created_at: string;
  last_used_at: string | null;
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
  const assertion = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufferToBase64Url(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bufferToBase64Url(assertion.authenticatorData),
      clientDataJSON: bufferToBase64Url(assertion.clientDataJSON),
      signature: bufferToBase64Url(assertion.signature),
      userHandle: assertion.userHandle ? bufferToBase64Url(assertion.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

async function requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, { credentials: "include", ...init });
  const text = await res.text();
  if (!res.ok) throw new Error(`${init.method ?? "GET"} ${path} -> ${res.status} ${text}`);
  return text ? (JSON.parse(text) as T) : (undefined as T);
}

async function getJson<T>(path: string): Promise<T> {
  return requestJson<T>(path);
}

async function postJson<T>(path: string, body?: unknown): Promise<T> {
  return requestJson<T>(path, {
    method: "POST",
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function deleteJson(path: string): Promise<void> {
  await requestJson<void>(path, { method: "DELETE" });
}

async function finishRegistration<T>(
  start: Challenge<ServerCreationOptions>,
  finishPath: string,
  name?: string,
): Promise<T> {
  const cred = (await navigator.credentials.create(
    decodeCreationOptions(start.options),
  )) as PublicKeyCredential | null;
  if (!cred) throw new Error("user cancelled passkey registration");
  return postJson<T>(finishPath, {
    challenge_id: start.challenge_id,
    response: encodeAttestation(cred),
    name,
  });
}

export async function requestSignup(email: string): Promise<void> {
  await postJson<void>("/auth/signup/request", { email });
}

export async function finishSignup(token: string, passkeyName?: string): Promise<AuthResponse> {
  const start = await postJson<Challenge<ServerCreationOptions>>("/auth/signup/consume", { token });
  return finishRegistration<AuthResponse>(start, "/auth/signup/finish", passkeyName);
}

export async function requestRecovery(email: string): Promise<void> {
  await postJson<void>("/auth/recovery/request", { email });
}

export async function finishRecovery(token: string, passkeyName?: string): Promise<AuthResponse> {
  const start = await postJson<Challenge<ServerCreationOptions>>("/auth/recovery/consume", { token });
  return finishRegistration<AuthResponse>(start, "/auth/recovery/finish", passkeyName);
}

export async function registerPasskey(name?: string): Promise<PasskeyDto> {
  const start = await postJson<Challenge<ServerCreationOptions>>("/auth/passkey/register/start");
  return finishRegistration<PasskeyDto>(start, "/auth/passkey/register/finish", name);
}

export async function authenticatePasskey(): Promise<AuthResponse> {
  const start = await postJson<Challenge<ServerRequestOptions>>("/auth/passkey/authenticate/start");
  const cred = (await navigator.credentials.get(
    decodeRequestOptions(start.options),
  )) as PublicKeyCredential | null;
  if (!cred) throw new Error("user cancelled passkey authentication");
  return postJson<AuthResponse>("/auth/passkey/authenticate/finish", {
    challenge_id: start.challenge_id,
    response: encodeAssertion(cred),
  });
}

export async function listPasskeys(): Promise<PasskeyDto[]> {
  return getJson<PasskeyDto[]>("/auth/passkey");
}

export async function deletePasskey(credentialId: string): Promise<void> {
  await deleteJson(`/auth/passkey/${credentialId}`);
}

export async function listSessions(): Promise<SessionDto[]> {
  return getJson<SessionDto[]>("/auth/sessions");
}

export async function revokeSession(id: string): Promise<void> {
  await deleteJson(`/auth/sessions/${id}`);
}

export async function revokeOtherSessions(): Promise<void> {
  await deleteJson("/auth/sessions");
}
