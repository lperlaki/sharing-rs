//! Secret Sharing
use crate::{
    ids::RabinInformationDispersal,
    share::{KrawczykShare, RabinShare, ShamirShare, ShareVec},
    Sharing,
};
use gf::{Field, GF};
use rand::Rng;
use std::cell::RefCell;
use stream_cipher::{NewStreamCipher, StreamCipher};
use std::io::{Read, self};

/// # Shamir Secret Sharing
///
/// ```rust
/// use sharing::{ShamirSecretSharing, Sharing};
///
/// let data = [1, 2, 3, 4, 5].to_vec();
///
/// let sharer = ShamirSecretSharing::new(5, 3, rand::thread_rng());
///
/// let shares = sharer.share(data.clone()).unwrap();
/// // You only need 3 out of the 5 shares to reconstruct
/// let rec = sharer.recontruct(shares[1..=3].to_vec()).unwrap();
///
/// assert_eq!(data, rec);
/// ```
pub struct ShamirSecretSharing<R: Rng> {
    n: u8,
    k: u8,
    rng: RefCell<R>,
}

impl<R: Rng> ShamirSecretSharing<R> {
    pub fn new(n: u8, k: u8, rng: R) -> Self {
        if k < 1 || k > n {
            panic!("n musst be bigger then k")
        }
        Self {
            n,
            k,
            rng: RefCell::new(rng),
        }
    }
}

impl<R: Rng> Sharing for ShamirSecretSharing<R> {
    type Share = ShamirShare;
    fn share(&self, data: &mut impl Read) -> io::Result<Vec<Self::Share>> {

        let mut rand = vec![0u8; self.k as usize];
        Ok(data.bytes().filter_map(|b| b.ok()).map(|byte| {

            rand[0] = byte;

            self.rng.borrow_mut().fill(&mut rand[1..]);
            (1..=self.n).map(|x| rand
                    .iter()
                    .enumerate()
                    .map(|(j, r)| (GF(x).pow(j) * GF(*r)))
                    .sum::<GF<u8>>().into())
        }).enumerate().fold(ShareVec::with_size(self.n as usize, 0), |shares, (j, bytes)| { 
            for (i, b) in bytes.enumerate() {
                shares[j].body[i] = b
            }
            shares
        }))
    }

    fn recontruct(&self, shares: Vec<Self::Share>) -> Option<Vec<u8>> {
        if shares.len() < self.k as usize {
            return None;
        }
        Some(
            (0..shares.size())
                .map(|i| {
                    (0..self.k as usize)
                        .map(|j| {
                            GF(shares[j].body[i])
                                * (0..self.k as usize)
                                    .filter(|m| *m != j)
                                    .map(|m| {
                                        GF(shares[m].id) / (GF(shares[m].id) - GF(shares[j].id))
                                    })
                                    .product::<GF<u8>>()
                        })
                        .sum::<GF<u8>>()
                        .into()
                })
                .collect(),
        )
    }
}

use std::marker::PhantomData;

/// # Krawczyk Secret Sharing
///
/// ```rust
/// use sharing::{KrawczykSecretSharing, Sharing};
///
/// let data = [1, 2, 3, 4, 5].to_vec();
///
/// let sharer = KrawczykSecretSharing::<chacha20::ChaCha20, _>::new(5, 3, rand::thread_rng());
///
/// let shares = sharer.share(data.clone()).unwrap();
/// // You only need 3 out of the 5 shares to reconstruct
/// let rec = sharer.recontruct(shares[1..=3].to_vec()).unwrap();
///
/// assert_eq!(data, rec);
/// ```
pub struct KrawczykSecretSharing<C: StreamCipher + NewStreamCipher, R: Rng> {
    rng: RefCell<R>,
    shamir: ShamirSecretSharing<R>,
    rabin: RabinInformationDispersal,
    phantom: PhantomData<C>,
}

impl<R: Rng + Clone, C: StreamCipher + NewStreamCipher> KrawczykSecretSharing<C, R> {
    pub fn new(n: u8, k: u8, rng: R) -> Self {
        Self {
            rng: RefCell::new(rng.clone()),
            shamir: ShamirSecretSharing::new(n, k, rng),
            rabin: RabinInformationDispersal::new(n, k),
            phantom: PhantomData,
        }
    }
}

impl<R: Rng, C: StreamCipher + NewStreamCipher> Sharing for KrawczykSecretSharing<C, R> {
    type Share = KrawczykShare;
    fn share(&self, data: &mut impl Read) -> io::Result<Vec<Self::Share>> {
        let mut buf = Vec::new();
        data.read_to_end(&mut buf);
        let length = buf.len();
        let key_nonce = {
            let mut rand = [0u8; 44];
            self.rng.borrow_mut().fill(&mut rand[..]);
            rand
        };
        let mut cipher = C::new_var(&key_nonce[0..32], &key_nonce[32..44]).expect("Use ChaCha20 Stream Cipher");
        
        cipher.encrypt(&mut buf);
        let shares = self.rabin.share(&mut buf[..])?;

        let key_nonce_shares = self.shamir.share(&mut key_nonce[..])?;

        Ok(
            shares
                .into_iter()
                .zip(key_nonce_shares)
                .map(|(r, s)| KrawczykShare {
                    id: r.id,
                    length,
                    key: {
                        let mut a = [0u8; 44];
                        a.copy_from_slice(&s.body[0..44]);
                        a
                    },
                    body: r.body,
                })
                .collect(),
        )
    }

    fn recontruct(&self, shares: Vec<Self::Share>) -> Option<Vec<u8>> {
        let (shamir_shares, rabin_shares): (Vec<_>, Vec<_>) = shares
            .into_iter()
            .map(|s| {
                (
                    ShamirShare {
                        id: s.id,
                        body: s.key.to_vec(),
                    },
                    RabinShare {
                        id: s.id,
                        length: s.length,
                        body: s.body,
                    },
                )
            })
            .unzip();
        let key_nonce = self.shamir.recontruct(shamir_shares)?;
        let mut data = self.rabin.recontruct(rabin_shares)?;
        let mut cypher = C::new_var(&key_nonce[0..32], &key_nonce[32..44]).expect("Use ChaCha20 Stream Cipher");
        cypher.decrypt(&mut data);
        Some(data)
    }
}
