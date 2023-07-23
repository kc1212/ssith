pub(crate) const KEY_SIZE: usize = 16;
pub(crate) const BLOCK_SIZE: usize = 16;
pub(crate) const OPENING_SIZE: usize = 16;
pub(crate) const DIGEST_SIZE: usize = 32;

pub(crate) const PREFIX_H1_DELTA: [u8; 8] = *b"delta_rs";
pub(crate) const PREFIX_H1_COM: [u8; 8] = *b"commitme";
pub(crate) const PREFIX_H2: [u8; 8] = *b"h1s-----";
pub(crate) const PREFIX_WITNESS: [u8; 8] = *b"witness-";
pub(crate) const PREFIX_INSTANCE: [u8; 8] = *b"instance";
