# AvoKind Growth Dashboard

Private dashboard published with GitHub Pages. `index.html` is a login page whose dashboard
(including all data) is encrypted with AES-256-GCM, using a key derived from the password with
PBKDF2-SHA256 (600,000 iterations). It is decrypted only in the viewer's browser; without the
password the file is unreadable. The plaintext dashboard is never committed.

## Weekly update

1. Update `../AvoKind Dashboard.html` (data comes from the "ACR Report" tab of the AvoKind WEEKLY Report).
2. `node encrypt.mjs` (reads the password from the macOS Keychain).
3. Commit and push `index.html`.

## Change the password

`node encrypt.mjs --set-password`, then rebuild and push. Delete `crypto.json` first if you
also want everyone's "remember me" to stop working.
