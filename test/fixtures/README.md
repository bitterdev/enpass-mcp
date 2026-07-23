# Test fixtures

These are **genuine SQLCipher databases** in the Enpass vault format, used by the
test suite. They contain only dummy data and their master password is public:

```
Correct-Horse-Battery-Staple-9
```

- `fixture-v4.enpassdb` — `cipher_compatibility = 4` (Enpass 6.8+)
- `fixture-v3.enpassdb` — `cipher_compatibility = 3` (older Enpass 6 vaults)

Both use PBKDF2-HMAC-SHA512 with 100000 iterations and a 16-byte header salt,
matching how Enpass derives its raw SQLCipher key. They were generated with real
SQLCipher so the tests validate the derivation end to end.

Each vault seeds several entry types to prove type-agnostic reading: a login
(GitHub), a finance entry (Bank), a credit card (Visa Card, with sensitive card
number and CVC) and a secure note (Server Notes).

They also contain attachments:

- an inline attachment (`note.txt`, stored directly in the vault)
- an external attachment (`photo.bin`, 4 KB) whose bytes live in
  `att-ext-1.enpassattach`, encrypted with a per-file key stored in the vault

Regenerate everything with:

```bash
npm install --no-save @journeyapps/sqlcipher
npm run generate-fixtures
```

Do not put real credentials here.
