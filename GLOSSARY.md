# doorman

Passkey-only authentication for a single application: passkeys are the only way to log in, and email exists only to start signup or recovery.

## Language

**Application**: The single website doorman authenticates users for. _Avoid_: relying party (outside WebAuthn specifics), tenant

**User**: A person known to the application, identified by an email address and holding one or more passkeys. _Avoid_: account

**Passkey**: A WebAuthn credential held on the user's device, and the only way to log in. _Avoid_: credential, authenticator (the authenticator is the device, not the key)

**Passkey registration**: The WebAuthn ceremony that creates one passkey, whether during signup, during recovery, or when adding another passkey. _Avoid_: enrollment

**Session**: A logged-in period that begins with a passkey login, signup, or recovery, and ends when it expires or is revoked.

**Email link**: A single-use link, bound to one purpose, that proves control of an email address. It never starts a session by itself. _Avoid_: magic link, verification link

**Signup**: Creating a new user through an email link, followed by registration of their first passkey.

**Recovery**: Regaining access to a user through an email link, followed by registration of a new passkey. _Avoid_: reset, re-enrolment

**Destructive action**: An action that could lock the real owner out of their user. _Avoid_: protected action, sensitive action

**Recovery cool-down**: The period after a recovery during which destructive actions are refused. _Avoid_: restricted session, cooldown

**Re-authentication**: Proving possession of a passkey again, within an existing session, right before a destructive action. `reauth` is the accepted abbreviation in identifiers. _Avoid_: step-up
