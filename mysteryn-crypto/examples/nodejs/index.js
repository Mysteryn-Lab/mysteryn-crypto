import {
  createSecret,
  did2public,
  public2debug,
  public2did,
  secret2debug,
  secret2public,
  sign,
  signature2debug,
  verify,
  did2debug,
  did2document,
  list_supported
} from "mysteryn-crypto"

const ED25519_SECRET = 0x1300
console.log("Using Multikey ED25519 algorithm")

const secret = createSecret(ED25519_SECRET, null, null, "secret", "pub", null)
console.log("Secret key:", secret)

const key = secret2public(secret)
console.log("Public key:", key)

const did = public2did(key)
console.log("DID:", did)

const obj = {
  a: "test",
  b: 1
}
console.log("Data:", obj)

const data = new TextEncoder().encode(JSON.stringify(obj))

const signature = await sign(data, secret)
console.log("Signature:", signature)

// verify with a public key
await verify(data, key, signature)

// verify with the DID
const key2 = did2public(did)
await verify(data, key2, signature)

console.log("Successfully signed and verified data.")

console.log("\n----- Debug -----")
console.log(secret2debug(secret))
console.log(public2debug(key))
console.log(signature2debug(signature))
console.log(did2debug(did))

console.log("\n----- Did document -----")
console.log(did2document(did))

console.log("\n----- Secret Did document -----")
console.log(did2document(did, undefined, secret))

console.log("\n----- Supported algorithms -----")
console.log(list_supported())

/*
Expected output:

```text
Using Multikey ED25519 algorithm
Secret key: secret_xa82qzvpnnv43hyet5qgqjp95ktz285fznckq5rf7t8cxl5acuxsgdvvyuul2z7qd7j3htamq8pcphqatz0xdgsn0280ja7
Public key: pub_xa8tkszqmsw43qzqfqtnwp7hplj9lgcfyrvy9wqhsj7sa2m3ks7l5837g2l3rrlx435qegz4k5ah6kw5a7
DID: did:key:pub_xa8tkszqmsw43qzqfqtnwp7hplj9lgcfyrvy9wqhsj7sa2m3ks7l5837g2l3rrlx435qegz4k5ah6kw5a7
Data: { a: 'test', b: 1 }
Signature: zKEPzYdqYNDhFu4rgaV8xeyFNH6yfCzPs3uN2eLJwLmU2dEqmRLaBYH4hzEi4zHx4Vp7mnFwp9v8a5hh5iwrF5aQAyebtHd2pQKTg7EPU9s1GRWGgVage
Successfully signed and verified data.

----- Debug -----
MultikeySecretKey(#algorithm_name: EdDSA, codec: 0x1300, hrp: secret, key_size: 32, key: Ed25519(Ed25519SecretKey(zB8q83XttGdFv1tpCHkT9E8HgSHh65einmZo21UU8TVqQ)))
MultikeyPublicKey(#algorithm_name: EdDSA, codec: 0xed, hrp: pub, key_size: 32, key: Ed25519(Ed25519PublicKey(z7FVBmXZjy2SnEHWCvQTcy8uQ5nXNxcn2PWVRUVvszKqb)))
Multisig(#algorithm_name: EdDSA, codec: 0xed, nonce_size: 12, nonce: zMG5kbWyTRe4EUicv, signature_size: 64, signature: Ed25519(Ed25519Signature(zKEPzYdqYNDhFu4rgaV8xeyFNH6yfCzPs3uN2eLJwLmU2dEqmRLaBYH4hzEi4zHx4Vp7mnFwp9v8a5hh5iwrF5aQAyebtHd2pQKTg7EPU9s1GRWGgVage)))
Did(did: did:key:pub_xa8tkszqmsw43qzqfqtnwp7hplj9lgcfyrvy9wqhsj7sa2m3ks7l5837g2l3rrlx435qegz4k5ah6kw5a7, method: did:key, algorithm: 0x3a, key: zz3JBeQtrhL6yLFuv2zo5poxjbYuFeXqWKzHmQH2jZ7xkhvW53KJiP4roj, url: pub_xa8tkszqmsw43qzqfqtnwp7hplj9lgcfyrvy9wqhsj7sa2m3ks7l5837g2l3rrlx435qegz4k5ah6kw5a7)
```
*/
