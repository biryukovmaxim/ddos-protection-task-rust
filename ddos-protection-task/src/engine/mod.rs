use crate::challenge::Engine as Interface;
use crate::hashcash::Hashcash;
use aya::maps::{HashMap, MapRefMut};
use dashmap::DashMap;
use ddos_protection_task_common::SocketV4;
use log::debug;
use std::sync::Mutex;
use std::{net::SocketAddrV4, sync::Arc};

pub mod error;

pub struct Engine<D: digest::Digest> {
    difficulty: u32,
    challenges: Arc<DashMap<<Self as Interface>::UK, <Self as Interface>::Challenge>>,
    whitelist: Arc<Mutex<HashMap<MapRefMut, SocketV4, u32>>>,
}

impl<D: digest::Digest> Engine<D> {
    pub fn new(difficulty: u32, whitelist: Arc<Mutex<HashMap<MapRefMut, SocketV4, u32>>>) -> Self {
        Self {
            difficulty,
            challenges: Arc::new(Default::default()),
            whitelist,
        }
    }
}

impl<D: digest::Digest> Interface for Engine<D> {
    type Challenge = [u8; 8];
    type UK = SocketAddrV4;
    type Error = error::Error;

    fn create_challenge(&self, uk: &Self::UK) -> Result<Self::Challenge, Self::Error> {
        let challenge = rand::random();
        let old = self.challenges.insert(*uk, challenge);
        debug!("insert new challenge, key: {uk}, old: {old:?}, new: {challenge:?}");

        Ok(challenge)
    }

    fn check_solution(
        &self,
        uniq_key: &Self::UK,
        hash: [u8; 32],
        nonce: u64,
    ) -> Result<bool, Self::Error> {
        let challenge = self
            .challenges
            .get(uniq_key)
            .ok_or(error::Error::ChallengeNotFound)?;
        let address_bytes = uniq_key.ip().octets();
        let port_bytes: [u8; 2] = uniq_key.port().to_be_bytes();
        let mut data = [0; 8 + 4 + 2];
        data[0..8].copy_from_slice(challenge.as_ref());
        data[8..12].copy_from_slice(&address_bytes);
        data[12..].copy_from_slice(&port_bytes);
        let hk = Hashcash::<[u8; 14], D>::new(data);

        let success = hk.verify(hash, nonce, self.difficulty);
        if success {
            self.whitelist.lock().unwrap().insert(
                SocketV4::new(u32::from_be_bytes(uniq_key.ip().octets()), uniq_key.port()),
                1,
                0,
            )?;
        }
        Ok(success)
    }
}
