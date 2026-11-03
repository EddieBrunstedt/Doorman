# doorman

Passkey-only authentication for a single application: passkeys are the only way to log in, and email exists only to start signup or recovery, or to change a user's email address.

## Language

**Application**: The single website doorman authenticates users for. _Avoid_: relying party, tenant

**User**: A person known to the application, identified by an email address and holding one or more passkeys. _Avoid_: account

**Disabled user**: A user an operator has barred from logging in and from recovery until an operator enables them again. _Avoid_: suspended, locked, frozen

**Operator**: Someone who acts on a user for the application, such as support staff, rather than as that user. _Avoid_: admin, administrator

**Passkey**: A WebAuthn credential held by an authenticator, and the only way to log in. _Avoid_: credential

**Authenticator**: The device or password manager that holds a user's passkeys and verifies the user before using one.

**Passkey registration**: The WebAuthn ceremony that creates one passkey, whether during signup, during recovery, or when adding another passkey. _Avoid_: enrollment

**Login**: Starting a session by proving possession of a passkey, without first saying who the user is. _Avoid_: sign-in

**Session**: A logged-in period that begins with a login, signup, or recovery, and ends when it expires or is revoked.

**Cookie session**: A session whose token travels only in an HttpOnly cookie, so no page script can read it. Every session a browser starts is one. `SessionTransport::Cookie` in identifiers.

**DPoP session**: A session whose token travels only in an `Authorization: DPoP` header, beside a DPoP proof signed by the key the session started with, so the token is useless without that key. Only a DPoP client can start one, and only when the host allows DPoP sessions. `SessionTransport::Dpop` in identifiers. _Avoid_: bearer session

**DPoP client**: A client other than a browser, such as a native app, that holds a private key of its own and asks for a DPoP session. _Avoid_: bearer client

**Session token**: The opaque secret a client presents to name its session. The client holds it; the server stores only its hash. `SessionToken` in identifiers. _Avoid_: credential

**Email link**: A single-use link, bound to one purpose, that proves control of an email address. It never starts a session by itself. _Avoid_: magic link, verification link, verification token

**Link template**: The absolute URL, holding a `{token}` placeholder, that the host gives doorman for each email link purpose (signup, recovery and email change). doorman puts each link's token in place of the placeholder, so the link opens a page of the application. `LinkTemplate` in identifiers. _Avoid_: URL template, email template

**Redeem**: To use up a single-use secret, such as an email link, so that it can never be used again. _Avoid_: consume

**Signup**: Creating a new user through an email link, followed by registration of their first passkey.

**Recovery**: Regaining access to a user who has finished signup, through an email link, followed by registration of a new passkey. _Avoid_: reset, re-enrolment

**Email change**: Replacing a user's email address with a new one, proven through an email link sent to the new address.

**Security notice**: An email telling a user that something affecting their security happened, such as a passkey being removed or a recovery being requested. _Avoid_: notification, alert

**Email template**: The wording of one kind of email doorman sends, either the email that carries an email link or a security notice: its subject, its text body and, optionally, an HTML body. doorman fills in what each email needs, such as its email link or a passkey's name, then addresses it and hands it to the host to deliver. The host may replace any template; doorman has its own for each. `EmailTemplates` in identifiers. _Avoid_: message template, email copy

**Destructive action**: An action that someone holding a stolen session could use to lock the real user out. _Avoid_: protected action, sensitive action

**Recovery cool-down**: The period after a recovery during which destructive actions are refused to every session that started from the recovered passkey, or from a passkey added in one of those sessions, and none of those passkeys can re-authenticate. The user's other passkeys and their sessions are unaffected. `cool_down` is its spelling in identifiers. _Avoid_: restricted session, cooldown

**Re-authentication**: Proving possession of a passkey again, within an existing session, right before a destructive action. `reauth` is the accepted abbreviation in identifiers. _Avoid_: step-up

**Record stores**: The stores that hold users and their passkeys. Their rows never expire; they last until doorman deletes them. `records` is their spelling in identifiers. _Avoid_: system of record, durable

**Expiring stores**: The stores that hold sessions, email links, passkey challenges and used DPoP proofs. Every row in them expires and is purged once it has. `expiring` is their spelling in identifiers. _Avoid_: ephemeral

**Purge schedule**: How the expiring stores' expired rows get purged: on an interval, from the process that serves the application, or by a separate process that a scheduler outside doorman runs. The host must choose one. `PurgeSchedule` in identifiers.

**Namespace**: The name the Redis adapter puts at the start of every key it writes, so that one application's expiring stores and rate limits stay apart from anything else on the same Redis server, such as another deployment of the same application. `doorman` unless the host sets another. _Avoid_: key prefix, tenant

## WebAuthn specifics

Where doorman speaks the WebAuthn protocol itself, it keeps WebAuthn's own names: relying party (with its ID, name and origin), credential (only in the protocol's own messages and fields, such as the credential ID), user handle, user verification, discoverable credential, ceremony, challenge, assertion and attestation. Everywhere else, the terms above apply.

## DPoP specifics

Where doorman speaks DPoP (RFC 9449) itself, it keeps that protocol's own names: DPoP proof, JWK thumbprint (`jkt`), and the proof's claims (`jti`, `htm`, `htu`, `iat`, `ath`).
