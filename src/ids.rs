//! Information Dispersal Algorithms
use crate::{
    share::{RabinShare, ShareVec},
    Sharing,
};
use gf::{Field, GF};


/// # Rabin Information Dispersal
/// 
/// ```rust
/// use sharing::{RabinInformationDispersal, Sharing};
/// 
/// let data = [1, 2, 3, 4, 5].to_vec();
/// 
/// let sharer = RabinInformationDispersal::new(5, 3);
///
/// let shares = sharer.share(data.clone()).unwrap();
/// // You only need 3 out of the 5 shares to reconstruct
/// let rec = sharer.recontruct(shares[1..=3].to_vec()).unwrap();
///
/// assert_eq!(data, rec);
/// ```
pub struct RabinInformationDispersal {
    n: u8,
    k: u8,
}

impl RabinInformationDispersal {
    pub fn new(n: u8, k: u8) -> Self {
        Self { n, k }
    }
}

impl Sharing for RabinInformationDispersal {
    type Share = RabinShare;
    fn share(&self, data: Vec<u8>) -> Option<Vec<Self::Share>> {
        let length = data.len();
        Some(
            (1..=self.n)
                .map(|x| {
                    let gx = GF(x);
                    RabinShare {
                        id: x,
                        length,
                        body: data
                            .chunks(self.k as usize)
                            .map(|chunk| {
                                chunk
                                    .into_iter()
                                    .rev()
                                    .fold(GF::zero(), |res, b| GF(*b) + gx * res)
                                    .into()
                            })
                            .collect(),
                    }
                })
                .collect(),
        )
    }

    fn recontruct(&self, shares: Vec<Self::Share>) -> Option<Vec<u8>> {
        if shares.len() < self.k as usize {
            return None;
        }
        let xvalues = shares.iter().map(|x| x.id).collect();
        let decoder = generate_decoder(self.k as usize, xvalues);
        let mut secret = vec![0u8; shares.size()];
        for i in 0..shares[0].body.len() {
            for j in 0..self.k as usize {
                let index = (i * self.k as usize) + j;
                if index >= shares.size() { continue; }
                secret[index] = (0..self.k as usize)
                    .map(|x| GF(decoder[j][x]) * GF(shares[x].body[i]))
                    .sum::<GF<u8>>()
                    .into();
            }
        }
        Some(secret)
    }
}

fn generate_decoder(size: usize, values: Vec<u8>) -> Vec<Vec<u8>> {
    inverse(
        (0..size)
            .map(|i| (0..size).map(|j| GF(values[i]).pow(j).into()).collect())
            .collect(),
    )
}

fn two_mut<T>(sl: &mut [T], i: usize, j: usize) -> (&mut T, &mut T) {
    let (smaller, lagger) = if i < j { (i, j) } else { (j, i) };
    let (smsl, lgsl) = sl.split_at_mut(lagger);
    if i == smaller {
        (&mut smsl[smaller], &mut lgsl[0])
    } else {
        (&mut lgsl[0], &mut smsl[smaller])
    }
}

fn inverse(matrix: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let size = matrix.len();
    let mut res = generate_identity(size);
    let mut tmp = matrix.clone();

    for i in 0..size {
        // if tmp[i][i] == 0 && !find_and_swap_nonzero_in_row(i, size, &mut tmp, &mut res) {
        //   size = size - 1;
        // }

        let inv = GF(tmp[i][i]).inverse().into();
        normalize_row(&mut tmp[i][..], &mut res[i][..], inv);

        for j in 0..size {
            if j == i {
                continue;
            }
            let coeff = tmp[j][i];
            if coeff == 0 {
                continue;
            }

            let (tmpi, tmpj) = two_mut(&mut tmp[..], i, j);
            let (resi, resj) = two_mut(&mut res[..], i, j);
            mult_and_subtract(&mut tmpj[..], &mut tmpi[..], coeff);
            mult_and_subtract(&mut resj[..], &mut resi[..], coeff);
        }
    }

    // we could assert here that tmp is now an identity matrix

    return res;
}

fn mult_and_subtract(row: &mut [u8], normalized: &[u8], coeff: u8) {
    for i in 0..row.len() {
        row[i] = (GF(row[i]) - GF(normalized[i]) * GF(coeff)).into();
    }
}

fn normalize_row(tmp_row: &mut [u8], res_row: &mut [u8], element: u8) {
    for i in 0..tmp_row.len() {
        tmp_row[i] = (GF(tmp_row[i]) * GF(element)).into();
        res_row[i] = (GF(res_row[i]) * GF(element)).into();
    }
}

// fn find_and_swap_nonzero_in_row(
//     i: usize,
//     num_rows: usize,
//     tmp: &mut Vec<Vec<u8>>,
//     res: &mut Vec<Vec<u8>>,
// ) -> bool {
//     for j in i + 1..num_rows {
//         if tmp[j][i] != 0 {
//             swap_rows(tmp, i, j);
//             swap_rows(res, i, j);
//             return true;
//         }
//     }
//     false
// }

// fn swap_rows(matrix: &mut Vec<Vec<u8>>, first: usize, second: usize) {
//     matrix.swap(first, second);
// }

fn generate_identity(size: usize) -> Vec<Vec<u8>> {
    (0..size)
        .map(|i| (0..size).map(|j| if i == j { 1 } else { 0 }).collect())
        .collect()
}
