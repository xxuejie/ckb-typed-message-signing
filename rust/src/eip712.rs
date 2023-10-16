//! This module adds support for transforming a CKB TypedMessage to a
//! corresponding EIP-712 message, generating the exact same hash per EIP-712
//! spec. It is not directly used now(sighash-all message is generated now for
//! ExtendedWitness), but mostly put here for a reference and future-proof reason.

use crate::schemas::basic::{
    HashReader, HashUnionReader, StructReader, TypedMessage, TypedMessageReader,
    TypedMessageUnionReader, ValueReader, ValueUnionReader,
};
use ckb_std::{
    ckb_constants::Source,
    error::SysError,
    syscalls::{load_cell_data, load_transaction},
};
use molecule::{error::VerificationError, prelude::Reader};
use sha3::{Digest, Keccak256};

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum Error {
    MoleculeEncoding,
    Sys(SysError),
    CellDataEof,
    InvalidSource,
    InvalidBool,
    InvalidNumber,
    InvalidFixedBytes,
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

pub struct Eip712Hash(pub [u8; 32]);

impl TryFrom<&TypedMessage> for Eip712Hash {
    type Error = Error;

    fn try_from(message: &TypedMessage) -> Result<Self, Self::Error> {
        let reader = message.as_reader();
        Ok(Eip712Hash(build_typed_message_hash(&reader)?))
    }
}

pub fn build_typed_message_hash<'r>(
    typed_message: &TypedMessageReader<'r>,
) -> Result<[u8; 32], Error> {
    let eip712 = match typed_message.to_enum() {
        TypedMessageUnionReader::EIP712(eip712) => eip712,
    };

    let mut hasher = Keccak256::default();
    hasher.update(b"\x19\x01");
    hasher.update(fetch_hash(&eip712.domain_separator())?);
    hasher.update(hash_struct(&eip712.message())?);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hasher.finalize());
    Ok(result)
}

// Ouch
fn u64_to_source(source: u64) -> Result<Source, Error> {
    match source {
        s if s == Source::Input as u64 => Ok(Source::Input),
        s if s == Source::Output as u64 => Ok(Source::Output),
        s if s == Source::CellDep as u64 => Ok(Source::CellDep),
        s if s == Source::HeaderDep as u64 => Ok(Source::HeaderDep),
        s if s == Source::GroupInput as u64 => Ok(Source::GroupInput),
        s if s == Source::GroupOutput as u64 => Ok(Source::GroupOutput),
        _ => Err(Error::InvalidSource),
    }
}

fn fetch_hash<'r>(h: &HashReader<'r>) -> Result<[u8; 32], Error> {
    let mut result = [0u8; 32];
    match h.to_enum() {
        HashUnionReader::Byte32(hash) => {
            result.copy_from_slice(&hash.raw_data());
        }
        HashUnionReader::RefCell(ref_cell) => {
            let source = {
                let mut t = [0u8; 8];
                t.copy_from_slice(ref_cell.source().raw_data());
                u64::from_le_bytes(t)
            };
            let index = {
                let mut t = [0u8; 4];
                t.copy_from_slice(ref_cell.index().raw_data());
                u32::from_le_bytes(t)
            };
            let offset = {
                let mut t = [0u8; 4];
                t.copy_from_slice(ref_cell.offset().raw_data());
                u32::from_le_bytes(t)
            };
            match load_cell_data(
                &mut result,
                offset as usize,
                index as usize,
                u64_to_source(source)?,
            ) {
                Ok(n) => {
                    if n < 32 {
                        return Err(Error::CellDataEof);
                    }
                }
                Err(SysError::LengthNotEnough(_)) => (),
                Err(e) => return Err(e.into()),
            }
        }
        HashUnionReader::RefTransaction(ref_tx) => {
            let offset = {
                let mut t = [0u8; 4];
                t.copy_from_slice(ref_tx.offset().raw_data());
                u32::from_le_bytes(t)
            };
            match load_transaction(&mut result, offset as usize) {
                Ok(n) => {
                    if n < 32 {
                        return Err(Error::CellDataEof);
                    }
                }
                Err(SysError::LengthNotEnough(_)) => (),
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(result)
}

fn hash_struct(s: &StructReader) -> Result<[u8; 32], Error> {
    let mut hasher = Keccak256::default();
    hasher.update(fetch_hash(&s.type_hash())?);
    for i in 0..s.values().len() {
        let serialized_value = s.values().get_unchecked(i);
        let value = ValueReader::from_slice(serialized_value.raw_data())?;
        encode_value(&mut hasher, &value)?;
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&hasher.finalize());
    Ok(result)
}

fn encode_value<'r, D: Digest>(hasher: &mut D, value: &ValueReader<'r>) -> Result<(), Error> {
    match value.to_enum() {
        ValueUnionReader::Struct(s) => {
            let hash = hash_struct(&s)?;
            hasher.update(hash);
        }
        ValueUnionReader::Array(a) => {
            for i in 0..a.values().len() {
                let serialized_value = a.values().get_unchecked(i);
                let value = ValueReader::from_slice(serialized_value.raw_data())?;
                encode_value(hasher, &value)?;
            }
        }
        ValueUnionReader::Bool(b) => {
            if b.raw_data()[0] != 0 && b.raw_data()[0] != 1 {
                return Err(Error::InvalidBool);
            }
            encode_number(hasher, b.raw_data(), false)?;
        }
        ValueUnionReader::Bytes(b) => {
            let mut hasher2 = Keccak256::default();
            hasher2.update(b.raw_data());
            let mut result = [0u8; 32];
            result.copy_from_slice(&hasher2.finalize());
            hasher.update(result);
        }
        ValueUnionReader::String(s) => {
            let mut hasher2 = Keccak256::default();
            hasher2.update(s.raw_data());
            let mut result = [0u8; 32];
            result.copy_from_slice(&hasher2.finalize());
            hasher.update(result);
        }
        ValueUnionReader::Address(a) => {
            // Address is treated as uint160
            encode_number(hasher, a.raw_data(), false)?;
        }
        ValueUnionReader::FixedBytes(f) => {
            if f.len() > 32 {
                return Err(Error::InvalidFixedBytes);
            }
            let mut data = [0u8; 32];
            data[0..f.len()].copy_from_slice(f.raw_data());
            hasher.update(data);
        }
        ValueUnionReader::Int(i) => {
            encode_number(hasher, i.raw_data(), true)?;
        }
        ValueUnionReader::Uint(u) => {
            encode_number(hasher, u.raw_data(), false)?;
        }
    }
    Ok(())
}

fn encode_number<D: Digest>(hasher: &mut D, n: &[u8], signed: bool) -> Result<(), Error> {
    if n.len() > 32 {
        return Err(Error::InvalidNumber);
    }
    let fill = if signed {
        if n[0] & 0x80 != 0 {
            0xFF
        } else {
            0
        }
    } else {
        0
    };
    let mut data = [fill; 32];
    data[(32 - n.len())..32].copy_from_slice(n);
    hasher.update(data);
    Ok(())
}
