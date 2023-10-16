# ckb-typed-message-signing

A typed message signing library for Nervos CKB, inspired by [EIP-712](https://eips.ethereum.org/EIPS/eip-712).

It consists of 2 parts:

* A Rust crate used in CKB smart contracts for parsing, validating and generating signing message for signature validation;
* A TypeScript library that converts EIP-712 typed data to molecule based on-chain data structure, and vice versa.
