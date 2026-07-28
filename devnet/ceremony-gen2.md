# H.6 rotation — DKG generation 2

Run by rotate-ceremony.sh. Every value below was read back off the chain or off disk
after the fact, not carried forward from the step that produced it.

| | |
|---|---|
| contract | `0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0` (chain id 31337) |
| outgoing signer | `0xf97784e26938e046a7b389f865eb33fd75c0798f` (keyEpoch 2, DKG generation 1) |
| incoming signer | `0x4aa796c1774b2d60b897d75efcc3518d8a444c80` (keyEpoch 3, DKG generation 2) |
| incoming group key | `0x031cf260ce199fe608537748f0b0f21bf4c88b18e08523c79bfd4bcc7927423c04` |
| rotation digest | `0x301b767f6ea915cd44dde81b92c2984b01f7c703a3afdf54cea848525fecc859` |
| challenge window | 3600s |
| retired share tree | `devnet/shares-gen1` (retained on every node) |
| hand-off proof txid | `0xd4dee80d4e2e7292564d982394ac92a5b7a80cf1c3c41a0af3acb8bbec667050` |

The outgoing committee threshold-signed its own replacement; no admin key was used at any
point, and `breakGlassSetSigner` was not called. The retired committee's signature over the
step-8 mint preimage is valid — the signer's own ecrecover confirms it — and the contract
rejected it anyway with `BadSigner()`. That is the hand-off biting rather than a broken
signature, and it is the half of the claim that a moved pointer alone does not establish.

Transcripts: `/Users/mac/Niyas/projects/beldex/utils/local-devnet/.ceremony`
