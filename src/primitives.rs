use crate::consts::*;
use aes::cipher::{Block, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCore};
use serde::{Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use std::collections::VecDeque;

type Aes128Ctr = ctr::CtrCore<aes::Aes128, ctr::flavors::Ctr64BE>;
type PrgBlock = Block<aes::Aes128>;

#[derive(Debug, Eq, PartialEq)]
/// A hash-based opening of a commitment, created by the prover.
pub struct Opening {
    pub(crate) inner: [u8; OPENING_SIZE],
}

impl Serialize for Opening {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::serde::serialize(self.inner, serializer)
    }
}

impl Opening {
    pub(crate) fn new(c: [u8; OPENING_SIZE]) -> Self {
        Self { inner: c }
    }
}

#[derive(Debug, Eq, PartialEq)]
/// A hash-based commitment, created by the prover.
pub struct Commitment {
    // Usually we'd use Commitment(pub(crate) [u8; DIGEST_SIZE]),
    // but it seems tricky to make serde use hex encoding on the .0 field
    pub(crate) inner: [u8; DIGEST_SIZE],
}

impl Serialize for Commitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::serde::serialize(self.inner, serializer)
    }
}

impl Commitment {
    pub(crate) fn new(c: [u8; DIGEST_SIZE]) -> Self {
        Self { inner: c }
    }
}

pub(crate) fn fs_hash1(h: &[u8; DIGEST_SIZE]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(PREFIX_FS_H1);
    hasher.update(h);
    let result = hasher.finalize();
    result.as_slice().try_into().unwrap()
}

pub(crate) fn fs_hash2(
    h_prime: &[u8; DIGEST_SIZE],
    mseeds: &[[u8; BLOCK_SIZE]],
) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(PREFIX_FS_H2);
    hasher.update(h_prime);
    hasher.update(&mseeds.len().to_le_bytes());
    for mseed in mseeds {
        hasher.update(mseed);
    }
    let result = hasher.finalize();
    result.as_slice().try_into().unwrap()
}

pub(crate) fn hash1(delta_rs: &[u64], coms: &[Commitment]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(PREFIX_H1_DELTA);
    hasher.update(&delta_rs.len().to_le_bytes());
    for delta_r in delta_rs {
        hasher.update(&delta_r.to_le_bytes());
    }
    hasher.update(PREFIX_H1_COM);
    hasher.update(&coms.len().to_le_bytes());
    for com in coms {
        hasher.update(&com.inner);
    }

    let result = hasher.finalize();
    result.as_slice().try_into().unwrap()
}

pub(crate) fn hash2(h1s: &[[u8; DIGEST_SIZE]]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(PREFIX_H2);
    hasher.update(&h1s.len().to_le_bytes());
    for h1 in h1s {
        hasher.update(h1);
    }

    let result = hasher.finalize();
    result.as_slice().try_into().unwrap()
}

pub(crate) fn hash3<J>(rs_tilde: &[u8], t_shares: J) -> [u8; DIGEST_SIZE]
where
    J: Iterator<Item = u64>,
{
    let mut hasher = Sha3_256::new();
    hasher.update(PREFIX_H3);
    hasher.update(&rs_tilde.len().to_le_bytes());
    hasher.update(rs_tilde);

    // TODO add a prefix for number of t_shares for domain separation
    for t_share in t_shares {
        hasher.update(&t_share.to_le_bytes());
    }

    let result = hasher.finalize();
    result.as_slice().try_into().unwrap()
}

pub(crate) fn hash4<I>(h_primes: I) -> [u8; DIGEST_SIZE]
where
    I: Iterator<Item = [u8; DIGEST_SIZE]>,
{
    let mut hasher = Sha3_256::new();
    hasher.update(PREFIX_H4);

    // TODO add a prefix for number of h_prime for domain separation
    for h_prime in h_primes {
        hasher.update(&h_prime);
    }

    let result = hasher.finalize();
    result.as_slice().try_into().unwrap()
}

pub(crate) fn commit(value: &[u8], opening: &Opening) -> Commitment {
    debug_assert_eq!(Sha3_256::output_size(), DIGEST_SIZE);
    let mut hasher = Sha3_256::new();
    hasher.update(opening.inner);
    hasher.update(value);
    let result = hasher.finalize();
    // TODO avoid copying, change to generic array?
    Commitment::new(result.as_slice().try_into().unwrap())
}

pub(crate) fn verify(value: &[u8], opening: &Opening, commitment: &Commitment) -> bool {
    let actual = commit(value, opening);
    actual == *commitment
}

/// An AES counter mode based PRG.
/// Beware that the counter type is u64.
pub(crate) fn prg_aes_ctr(
    seed: &[u8; KEY_SIZE],
    iv: &[u8; BLOCK_SIZE],
    block_count: usize,
) -> Vec<[u8; BLOCK_SIZE]> {
    let mut cipher = Aes128Ctr::new(seed.into(), iv.into());
    debug_assert_eq!(Aes128Ctr::key_size(), KEY_SIZE);
    debug_assert_eq!(Aes128Ctr::iv_size(), BLOCK_SIZE);
    let mut blocks = vec![PrgBlock::default(); block_count];
    cipher.apply_keystream_blocks(&mut blocks);
    blocks
        .into_iter()
        .map(|gblock| gblock.as_slice().try_into().unwrap())
        .collect()
}

/// An AES counter mode based PRG that generates a vector of u64.
pub(crate) fn prg_u64(seed: &[u8; KEY_SIZE], iv: &[u8; BLOCK_SIZE], n: usize) -> Vec<u64> {
    const U64_BYTES: usize = u64::BITS as usize / 8;
    assert_eq!(BLOCK_SIZE % U64_BYTES, 0);
    let u64_per_block = BLOCK_SIZE / U64_BYTES;
    let block_count = (n + u64_per_block - 1) / u64_per_block;
    let blocks = prg_aes_ctr(seed, iv, block_count);

    let mut out = vec![0u64; n];
    for (i, block) in blocks.into_iter().enumerate() {
        let per_block = if i < block_count - 1 {
            u64_per_block
        } else {
            u64_per_block - (u64_per_block * block_count - n)
        };
        for j in 0..per_block {
            out[i * u64_per_block + j] = u64::from_le_bytes(
                block[j * U64_BYTES..j * U64_BYTES + 8]
                    .try_into()
                    .expect("must be 8 bytes"),
            );
        }
    }
    out
}

/// An AES counter mode based PRG that generates bits
/// every bit is represented by a u8.
pub(crate) fn prg_bin(seed: &[u8; KEY_SIZE], iv: &[u8; BLOCK_SIZE], n: usize) -> Vec<u8> {
    assert!(n >= 1);
    let block_count = n / BLOCK_SIZE + 1;
    let blocks = prg_aes_ctr(seed, iv, block_count);
    let mut out = vec![0u8; n];
    let mut i = 0usize;
    for block in blocks {
        for b in block {
            for shift in 0u8..8 {
                out[i] = (b >> shift) & 1;
                i += 1;
                if i == n {
                    return out;
                }
            }
        }
    }
    unreachable!()
}

/// A length doubling PRG based on AES counter mode.
pub(crate) fn prg_double(
    seed: &[u8; KEY_SIZE],
    iv: &[u8; BLOCK_SIZE],
) -> ([u8; BLOCK_SIZE], [u8; BLOCK_SIZE]) {
    let out = prg_aes_ctr(seed, iv, 2);
    (out[0], out[1])
}

/// A GGM tree PRG based on AES counter mode.
/// Internally, it is implemented using a queue since it is
/// easier to build an unbalanced tree when compared to the recursive method.
pub(crate) fn prg_tree(
    seed: &[u8; KEY_SIZE],
    iv: &[u8; BLOCK_SIZE],
    n: usize,
) -> Vec<[u8; BLOCK_SIZE]> {
    let mut out = VecDeque::with_capacity(n);
    while out.len() < n {
        if out.is_empty() {
            // NOTE: this assumes the key size is the same as the block size
            out.push_back(*seed);
            continue;
        }
        let new_seed: [u8; KEY_SIZE] = out.pop_front().expect("deque should be initialized here");
        let (left, right) = prg_double(&new_seed, iv);
        out.push_back(left);
        out.push_back(right);
    }
    out.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit() {
        let value = [0u8, 1, 2, 3];
        let opening = Opening::new([1u8; OPENING_SIZE]);
        let commitment = commit(&value, &opening);
        assert!(verify(&value, &opening, &commitment));

        let bad_opening = Opening::new([2u8; OPENING_SIZE]);
        assert!(!verify(&value, &bad_opening, &commitment));

        let bad_value = [0u8, 1, 2, 2];
        assert!(!verify(&bad_value, &opening, &commitment));
    }

    #[test]
    fn test_prg() {
        let seed = [0u8; KEY_SIZE];
        let iv = [0u8; BLOCK_SIZE];
        let out1 = prg_aes_ctr(&seed, &iv, 1);
        assert_eq!(out1.len(), 1);
        assert_eq!(out1[0].len(), BLOCK_SIZE);

        let out2 = prg_aes_ctr(&seed, &iv, 2);
        assert_eq!(out2.len(), 2);

        let seed2 = [1u8; KEY_SIZE];
        let out3 = prg_aes_ctr(&seed2, &iv, 1);
        assert_ne!(out1, out3);
    }

    #[test]
    fn test_prg_u64() {
        let seed = [0u8; KEY_SIZE];
        let iv = [0u8; BLOCK_SIZE];
        let out1 = prg_u64(&seed, &iv, 1);
        assert_eq!(out1.len(), 1);

        let out2 = prg_u64(&seed, &iv, 8);
        assert_eq!(out2.len(), 8);
    }

    #[test]
    fn test_prg_bin() {
        let seed = [0u8; KEY_SIZE];
        let iv = [0u8; BLOCK_SIZE];

        let out1 = prg_bin(&seed, &iv, 1);
        assert_eq!(out1.len(), 1);
        assert!(out1[0] == 0 || out1[0] == 1);

        let out2 = prg_bin(&seed, &iv, BLOCK_SIZE * 8);
        assert_eq!(out2.len(), BLOCK_SIZE * 8);
        for b in out2 {
            assert!(b == 0 || b == 1);
        }
    }

    #[test]
    fn test_prg_tree() {
        let seed = [0u8; KEY_SIZE];
        let iv = [0u8; BLOCK_SIZE];
        let out = prg_tree(&seed, &iv, 2);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].len(), BLOCK_SIZE);
        assert_eq!(out[1].len(), BLOCK_SIZE);
        assert_ne!(out[0], out[1]);
    }
}
