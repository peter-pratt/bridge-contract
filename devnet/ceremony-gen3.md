# H.6 rotation — DKG generation 3

Run by rotate-ceremony.sh. Every value below was read back off the chain or off disk
after the fact, not carried forward from the step that produced it.

| | |
|---|---|
| contract | `0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512` (chain id 31337) |
| outgoing signer | `0x838a9101e9d6e3230e826815082ff090d7d5b395` (keyEpoch 2, DKG generation 2) |
| incoming signer | `0x2f0a890f9e8effd65dee9d95ba8e174cdb1ffa2d` (keyEpoch 3, DKG generation 3) |
| incoming group key | `0x03b8ea73261ef93e0b31e14a363a5398ca96857d235bc2688e46f2f487a67479e0` |
| rotation digest | `0x8502e5921f26d4e9c1d8b0127c773d36dfd422380adcaae32f117f161e31871f` |
| challenge window | 120s |
| retired share tree | `devnet/shares-gen2` (retained on every node) |
| hand-off proof txid | `0x1e3803b9183d75031ebfd5c9c80221aaf61fe9564209a1c8bf40bbbe4f1c4588` |

The outgoing committee threshold-signed its own replacement; no admin key was used at any
point, and `breakGlassSetSigner` was not called. The retired committee's signature over the
step-8 mint preimage is valid — the signer's own ecrecover confirms it — and the contract
rejected it anyway with `BadSigner()`. That is the hand-off biting rather than a broken
signature, and it is the half of the claim that a moved pointer alone does not establish.

Transcripts: `/home/z044/Desktop/beldex/beldex/dkg-tss/beldex/utils/local-devnet/.ceremony`
