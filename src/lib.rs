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

mod share;
use share::Share;

#[doc(inline)]
pub use crate::{
    ids::RabinInformationDispersal,
    secret::{KrawczykSecretSharing, ShamirSecretSharing},
};

pub trait Sharing {
    type Share: Share;

    fn share(&self, data: Vec<u8>) -> Option<Vec<Self::Share>>;

    fn recontruct(&self, shares: Vec<Self::Share>) -> Option<Vec<u8>>;

    // fn reconstruct_partial<S: ShareVec>(&self, shares: S, start: i64) -> Result<Vec<u8>>;

    // fn recover<S: ShareVec>(&self, shares: S) -> Result<S>;
}

#[cfg(test)]
mod tests {}
