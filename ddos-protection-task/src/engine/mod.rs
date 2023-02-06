use crate::challenge::Engine as Interface;
use aya::maps::{HashMap, MapRefMut};
use dashmap::DashMap;
use ddos_protection_task_common::SocketV4;
use log::debug;
use std::{net::SocketAddrV4, sync::Arc};

pub mod error;

pub struct Engine<D: digest::Digest> {
    challenges: Arc<DashMap<<Self as Interface>::UK, <Self as Interface>::Challenge>>,
    whitelist: HashMap<MapRefMut, SocketV4, u32>,
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
        uk: &Self::UK,
        hash: [u8; 32],
        nonce: u64,
    ) -> Result<bool, Self::Error> {
        todo!()
    }
}
