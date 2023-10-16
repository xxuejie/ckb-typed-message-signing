#![no_std]

pub mod eip712;
pub mod schemas;

use crate::schemas::{
    basic::SighashWithAction,
    top_level::{ExtendedWitnessReader, ExtendedWitnessUnionReader},
};
use blake2b_ref::Blake2bBuilder;
use ckb_std::{
    ckb_constants::Source,
    error::SysError,
    high_level::{load_input_since, load_tx_hash, load_witness},
};
use molecule::{error::VerificationError, prelude::Reader};

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum Error {
    Sys(SysError),
    DuplicateAction,
    MoleculeEncoding,
    NotTypedTransaction,
    NotSighashVariant,
    NonEmptyGroupWitness,
}

impl From<SysError> for Error {
    fn from(e: SysError) -> Self {
        Error::Sys(e)
    }
}

impl From<VerificationError> for Error {
    fn from(_: VerificationError) -> Self {
        Error::MoleculeEncoding
    }
}

pub fn fetch_sighash_with_action() -> Result<SighashWithAction, Error> {
    let mut i = 0;
    let mut result = None;
    // Look for the first SighashWithAction witness
    while result.is_none() {
        match load_witness(i, Source::Input) {
            Ok(witness) => {
                if let Ok(r) = ExtendedWitnessReader::from_slice(&witness) {
                    if let ExtendedWitnessUnionReader::SighashWithAction(s) = r.to_enum() {
                        result = Some(s.to_entity());
                    }
                }
            }
            Err(SysError::IndexOutOfBound) => return Err(Error::NotTypedTransaction),
            Err(e) => return Err(e.into()),
        };
        i += 1;
    }
    let result = result.unwrap();
    // A single transaction must only have one SighashWithAction
    loop {
        match load_witness(i, Source::Input) {
            Ok(witness) => {
                if let Ok(r) = ExtendedWitnessReader::from_slice(&witness) {
                    if let ExtendedWitnessUnionReader::SighashWithAction(_) = r.to_enum() {
                        return Err(Error::DuplicateAction);
                    }
                }
            }
            Err(SysError::IndexOutOfBound) => return Ok(result),
            Err(e) => return Err(e.into()),
        }
    }
}

pub fn is_typed_transaction() -> bool {
    fetch_sighash_with_action().is_ok()
}

/// Generates sighash-all message hash for typed transaction. For performance
/// reason, this function requires the caller to ensure that current CKB
/// transaction is a typed transaction
pub fn generate_sighash_all_hash() -> Result<[u8; 32], Error> {
    let mut hasher = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    hasher.update(&load_tx_hash()?);

    // For the first witness, we will need to hash the action if available.
    {
        let witness = load_witness(0, Source::GroupInput)?;
        let extended_witness = ExtendedWitnessReader::from_slice(&witness)?;
        match extended_witness.to_enum() {
            ExtendedWitnessUnionReader::SighashWithAction(s) => {
                // This byte distinguishes SighashWithAction from Sighash
                hasher.update(&[1u8]);
                // Do we still need to hash the length of slice here? Since
                // molecule already validates the structure of the bytes, maybe
                // we can skip the length field?
                hasher.update(s.message().as_slice());
            }
            ExtendedWitnessUnionReader::Sighash(_) => {
                hasher.update(&[0u8]);
            }
            _ => return Err(Error::NotSighashVariant),
        }
    }
    // For the subsequent witnesses, we will ensure that they are empty
    {
        let mut i = 1;
        loop {
            match load_witness(i, Source::GroupInput) {
                Ok(w) => {
                    if w.len() > 0 {
                        return Err(Error::NonEmptyGroupWitness);
                    }
                }
                Err(SysError::IndexOutOfBound) => {
                    break;
                }
                Err(e) => return Err(e.into()),
            }
            i += 1;
        }
    }

    // Hash remaining witnesses that do not belong to any input cells
    {
        let mut i = calculate_inputs_len()?;
        loop {
            match load_witness(i, Source::Input) {
                Ok(w) => {
                    hasher.update(&(w.len() as u64).to_le_bytes());
                    hasher.update(&w);
                }
                Err(SysError::IndexOutOfBound) => {
                    break;
                }
                Err(e) => return Err(e.into()),
            }
            i += 1;
        }
    }

    let mut output = [0u8; 32];
    hasher.finalize(&mut output);

    Ok(output)
}

// Translated from https://github.com/nervosnetwork/ckb-system-scripts/blob/a7b7c75662ed950c9bd024e15f83ce702a54996e/c/common.h#L32-L66
fn calculate_inputs_len() -> Result<usize, SysError> {
    let mut lo = 0;
    let mut hi = 4;
    loop {
        match load_input_since(hi, Source::Input) {
            Ok(_) => {
                lo = hi;
                hi *= 2;
            }
            Err(SysError::IndexOutOfBound) => {
                break;
            }
            Err(e) => return Err(e),
        }
    }

    while (lo + 1) != hi {
        let i = (lo + hi) / 2;
        match load_input_since(i, Source::Input) {
            Ok(_) => {
                lo = i;
            }
            Err(SysError::IndexOutOfBound) => {
                hi = i;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(hi)
}
