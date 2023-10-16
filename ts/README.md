# ckb-typed-message-signing

TypeScript intergration for CKB typed message signing

## Usage

```typescript
// Given an EIP-712 formatted type data
const typedData = {
    types: {
        EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'verifyingContract', type: 'address' },
        ],
        Person: [
            { name: 'name', type: 'string' },
            { name: 'wallet', type: 'address' }
        ],
        Mail: [
            { name: 'from', type: 'Person' },
            { name: 'to', type: 'Person' },
            { name: 'contents', type: 'string' }
        ],
    },
    primaryType: 'Mail',
    domain: {
        name: 'Ether Mail',
        version: '1',
        chainId: 1,
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    },
    message: {
        from: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
    },
};

import { buildSighashWithActionWitness } from "ckb-typed-message-signing";

// Assuming user have signed the typed message, resulting in a signature:
const lock = "0xaabbcceedd....0000";

// Use the following code to build the final witness structure:
const data = serializeSighashWithActionWitness(typedData, lock);
// The generated data here shall be used for the witness containing typed
// message

// In the rare case, you might have serialized data in a witness(psuedo
// code is used below):
const witness = tx.get_witness(3);
// You can transform on-chain data structure back to EIP-712 style data:
import { parseSighashWithActionWitness } from "ckb-typed-message-signing";

// This is called dummyTypedData, since we would only need the typing
// definitions. The message field can be an empty object.
const dummyTypedData = {
    types: {
        EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'verifyingContract', type: 'address' },
        ],
        Person: [
            { name: 'name', type: 'string' },
            { name: 'wallet', type: 'address' }
        ],
        Mail: [
            { name: 'from', type: 'Person' },
            { name: 'to', type: 'Person' },
            { name: 'contents', type: 'string' }
        ],
    },
    primaryType: 'Mail',
    domain: {
        name: 'Ether Mail',
        version: '1',
        chainId: 1,
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    },
    message: {},
};

const [parsedTypedData, parsedLock] = parseSighashWithActionWitness(dummyTypedData, witness);
// parsedTypedData shall be the same (tho they might not be idential to each
// other, due to typing differences) from a user's perspective.

// For ease of usage, there is also support for serializing plain Sighash structure:
import { schema } from "ckb-typed-message-signing";
const lock2 = "0x112233112233";
const sighashWitness = schema.top_level.ExtendedWitness.pack({
  type: "Sighash",
  value: {
    lock: lock2
  },
});
const parsedSighashWitness = schema.top_level.ExtendedWitness.unpack(sighashWitness);
```
