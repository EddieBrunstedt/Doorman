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

**Email link**: A single-use link, bound to one purpose, that proves control of an email address. It never starts a session by itself. _Avoid_: magic link, verification link, verification token

**Redeem**: To use up a single-use secret, such as an email link, so that it can never be used again. _Avoid_: consume

**Signup**: Creating a new user through an email link, followed by registration of their first passkey.

**Recovery**: Regaining access to a user through an email link, followed by registration of a new passkey. _Avoid_: reset, re-enrolment

**Email change**: Replacing a user's email address with a new one, proven through an email link sent to the new address.

**Security notice**: An email telling a user that something affecting their security happened, such as a passkey being removed or a recovery being requested. _Avoid_: notification, alert

**Destructive action**: An action that someone holding a stolen session could use to lock the real user out. _Avoid_: protected action, sensitive action

**Recovery cool-down**: The period after a recovery during which destructive actions are refused to every session that started from the recovered passkey, or from a passkey added in one of those sessions. The user's other passkeys and their sessions are unaffected. `cool_down` is its spelling in identifiers. _Avoid_: restricted session, cooldown

**Re-authentication**: Proving possession of a passkey again, within an existing session, right before a destructive action. `reauth` is the accepted abbreviation in identifiers. _Avoid_: step-up

## WebAuthn specifics

Where doorman speaks the WebAuthn protocol itself, it keeps WebAuthn's own names: relying party (with its ID, name and origin), credential (only in the protocol's own messages and fields, such as the credential ID), user handle, user verification, discoverable credential, ceremony, challenge, assertion and attestation. Everywhere else, the terms above apply.
