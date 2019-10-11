//! Secret Sharing
use gf::{Field, GF};
use rand::Rng;
use shared_iter::{ShareIterator, SharedIter};

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
pub struct ShamirIterSecretSharing<R: Rng + Clone> {
    n: u8,
    k: u8,
    rng: R,
}

impl<R: Rng + Clone> ShamirIterSecretSharing<R> {
    pub fn new(n: u8, k: u8, rng: R) -> Self {
        Self { n, k, rng }
    }
}

pub struct ShareIter<'a, I: Iterator<Item = &'a u8>, R: Rng + Clone> {
    k: u8,
    pub x: u8,
    source: I,
    rng: SharedIter<rand::distributions::DistIter<rand::distributions::Standard, R, u8>>,
}

impl<'a, I: Iterator<Item = &'a u8>, R: Rng + Clone> Iterator for ShareIter<'a, I, R> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        let x = GF(self.x);
        self.source.next().map(|v| {
            std::iter::once(*v)
                .chain(self.rng.by_ref().take(self.k as usize - 1))
                .enumerate()
                .map(|(j, r)| (x.pow(j) * GF(r)))
                .sum::<GF<u8>>()
                .into()
        })
    }
}

impl<R: Rng + Clone> ShamirIterSecretSharing<R> {
    pub fn share<'a, I: Iterator<Item = &'a u8> + Clone>(
        &self,
        data: I,
    ) -> Option<Vec<ShareIter<'a, I, R>>> {
        let rng = self
            .rng
            .clone()
            .sample_iter::<u8, _>(rand::distributions::Standard)
            .share();
        Some((1..=self.n)
            .map(|x| ShareIter {
                k: self.k,
                x,
                source: data.clone(),
                rng: rng.clone(),
            })
            .collect())
    }
}
