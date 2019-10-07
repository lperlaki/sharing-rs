//! # Sharing
//! Use for example the Shamir implementation
//! ```rust
//! use sharing::{ShamirSecretSharing, Sharing};
//!
//! let data = [1, 2, 3, 4, 5].to_vec();
//!
//! let sharer = ShamirSecretSharing::new(5, 3, rand::thread_rng());
//!
//! let shares = sharer.share(data.clone()).unwrap();
//! // You only need 3 out of the 5 shares to reconstruct
//! let rec = sharer.recontruct(shares[1..=3].to_vec()).unwrap();
//!
//! assert_eq!(data, rec);
//! ```
pub mod ids;
pub mod secret;
pub mod secret_iter;

mod share;
use share::Share;

#[doc(inline)]
pub use crate::{
    ids::RabinInformationDispersal,
    secret::{KrawczykSecretSharing, ShamirSecretSharing},
    secret_iter::ShamirIterSecretSharing,
};

pub trait Sharing {
    type Share: Share;

    fn share(&self, data: Vec<u8>) -> Option<Vec<Self::Share>>;

    fn recontruct(&self, shares: Vec<Self::Share>) -> Option<Vec<u8>>;

    // fn reconstruct_partial<S: ShareVec>(&self, shares: S, start: i64) -> Result<Vec<u8>>;

    // fn recover<S: ShareVec>(&self, shares: S) -> Result<S>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iter() {
        let sharer1 = ShamirSecretSharing::new(3, 2, rand::thread_rng());

        let sharer2 = ShamirIterSecretSharing::new(3, 2, rand::thread_rng());

        let shares1 = sharer1.share([1, 2, 3, 4, 5].to_vec()).unwrap();

        let shares2: Vec<_> = sharer2
            .share([1, 2, 3, 4, 5].iter())
            .unwrap()
            .into_iter()
            .map(|i| share::ShamirShare {
                id: i.x,
                body: i.collect(),
            })
            .collect();
        assert_eq!(
            sharer1.recontruct(shares1[1..=2].to_vec()),
            sharer1.recontruct(shares2[1..=2].to_vec())
        );
    }
}
