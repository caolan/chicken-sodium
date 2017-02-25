# CHICKEN Scheme bindings to libsodium

A work in progress. See [libsodium.org](https://libsodium.org) for
more details.

Procedures:

- (sodium-init)
- (constant-time-blob=? a b len)
- (bin->hex bin)
- (hex->bin hex #!optional ignore)
- (generic-hash data #!key (size generic-hash-bytes) key) => blob
- (generic-hash-init #!key (size generic-hash-bytes) key) => state
- (generic-hash-update state data)
- (generic-hash-final state) => blob
- (sign-keypair) => (values public-key private-key)
- (sign-ed25519-secret-key->public-key secret-key) => public-key
- (sign-detached data secret-key) => signature
- (sign-verify-detached signature data public-key) => boolean
- (sign-ed25519-public-key->curve25519 ed25519-public-key) => curve25519-public-key
- (sign-ed25519-secret-key->curve25519 ed25519-secret-key) => curve25519-secret-key

Constants:

- generic-hash-bytes
- generic-hash-bytes-min
- generic-hash-bytes-max
- generic-hash-key-bytes
- generic-hash-key-bytes-min
- generic-hash-key-bytes-max
- sign-public-key-bytes
- sign-secret-key-bytes
- sign-bytes
- scalarmult-curve25519-bytes
