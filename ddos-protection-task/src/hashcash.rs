use digest::{Digest, Output};
use std::marker::PhantomData;

pub struct Hashcash<Data: AsRef<[u8]>, D: Digest> {
    data: Data,
    digest: PhantomData<D>,
}

impl<Data: AsRef<[u8]>, D: Digest> Hashcash<Data, D> {
    pub fn new(data: Data) -> Self {
        Self {
            data,
            digest: PhantomData,
        }
    }

    pub fn compute(&self, difficulty: u32) -> Option<(Output<D>, u64)> {
        let mut nonce = 0u64;
        while nonce < u64::MAX {
            let mut digest = D::new_with_prefix(&self.data);
            digest.update(nonce.to_be_bytes());
            let hash = digest.finalize();
            if Self::check_difficulty(hash.as_slice(), difficulty) {
                return Some((hash, nonce));
            }
            nonce += 1;
        }
        None
    }
    fn check_difficulty(hash: &[u8], difficulty: u32) -> bool {
        let mut zeroes = 0u32;
        for byte in hash {
            let z = byte.leading_zeros();
            zeroes += z;
            if z != 8 || zeroes >= difficulty {
                break;
            }
        }
        zeroes >= difficulty
    }

    pub fn verify(&self, input_hash: impl AsRef<[u8]>, nonce: u64, difficulty: u32) -> bool {
        let mut digest = D::new_with_prefix(&self.data);
        digest.update(nonce.to_be_bytes());
        let calculated_hash = digest.finalize();

        calculated_hash.as_slice() == input_hash.as_ref()
            && Self::check_difficulty(calculated_hash.as_ref(), difficulty)
    }
}
