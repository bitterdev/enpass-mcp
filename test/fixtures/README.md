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

Do not put real credentials here.
