//! Shamir secret sharing over `Fr` and Lagrange interpolation at zero.
//!
//! Backs both threshold BLS issuance (Mode A) and threshold ElGamal escrow
//! (Layer 3).

use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand, Zero};
use rapido_core::{Error, Result};

/// All `k`-subsets of `items`, in lexicographic order. Test-only: used to
/// exhaustively check threshold reconstruction over every authority subset.
#[cfg(test)]
pub(crate) fn combinations<T: Copy>(items: &[T], k: usize) -> Vec<Vec<T>> {
    if k == 0 {
        return vec![vec![]];
    }
    if items.len() < k {
        return vec![];
    }
    let mut out = Vec::new();
    for (i, it) in items.iter().enumerate() {
        for mut rest in combinations(&items[i + 1..], k - 1) {
            let mut v = vec![*it];
            v.append(&mut rest);
            out.push(v);
        }
    }
    out
}

/// One share of a secret. `index` is the evaluation point `x = index`; it is
/// 1-based because `x = 0` is the secret itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Share {
    pub index: u32,
    pub value: Fr,
}

impl Share {
    pub fn x(&self) -> Fr {
        Fr::from(self.index as u64)
    }
}

/// Split `secret` into `n` shares such that any `k` reconstruct it.
pub fn split<R: rand::Rng + ?Sized>(
    secret: Fr,
    k: usize,
    n: usize,
    rng: &mut R,
) -> Result<Vec<Share>> {
    if k == 0 || k > n {
        return Err(Error::InvalidParameter(format!("shamir: need 1 <= k <= n, got k={k}, n={n}")));
    }
    if n > u32::MAX as usize {
        return Err(Error::InvalidParameter("shamir: n too large".into()));
    }
    // coeffs[0] is the secret; the rest are the random polynomial coefficients.
    let mut coeffs = Vec::with_capacity(k);
    coeffs.push(secret);
    for _ in 1..k {
        coeffs.push(Fr::rand(rng));
    }
    Ok((1..=n as u32)
        .map(|i| {
            let x = Fr::from(i as u64);
            // Horner evaluation of the polynomial at x.
            let value = coeffs.iter().rev().fold(Fr::zero(), |acc, c| acc * x + c);
            Share { index: i, value }
        })
        .collect())
}

/// Lagrange basis coefficients evaluated at 0 for the given share indices.
///
/// `λ_i = Π_{j≠i} x_j / (x_j - x_i)`.
pub fn lagrange_at_zero(indices: &[u32]) -> Result<Vec<Fr>> {
    if indices.is_empty() {
        return Err(Error::NotEnoughShares { need: 1, got: 0 });
    }
    let mut sorted = indices.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != indices.len() {
        return Err(Error::InvalidParameter("shamir: duplicate share index".into()));
    }
    if sorted.first() == Some(&0) {
        return Err(Error::InvalidParameter("shamir: share index 0 is reserved".into()));
    }

    let xs: Vec<Fr> = indices.iter().map(|&i| Fr::from(i as u64)).collect();
    let mut out = Vec::with_capacity(xs.len());
    for (i, xi) in xs.iter().enumerate() {
        let mut num = Fr::from(1u64);
        let mut den = Fr::from(1u64);
        for (j, xj) in xs.iter().enumerate() {
            if i == j {
                continue;
            }
            num *= xj;
            den *= *xj - xi;
        }
        let inv = den.inverse().ok_or_else(|| {
            Error::InvalidParameter("shamir: singular Lagrange denominator".into())
        })?;
        out.push(num * inv);
    }
    Ok(out)
}

/// Reconstruct the secret from at least `k` shares.
pub fn reconstruct(shares: &[Share], k: usize) -> Result<Fr> {
    if shares.len() < k {
        return Err(Error::NotEnoughShares { need: k, got: shares.len() });
    }
    let subset = &shares[..k];
    let idx: Vec<u32> = subset.iter().map(|s| s.index).collect();
    let coeffs = lagrange_at_zero(&idx)?;
    Ok(subset.iter().zip(coeffs).map(|(s, l)| s.value * l).sum())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng_from_seed;

    /// Every `C(n, k)` subset must reconstruct, and no subset of `k-1` may.
    #[test]
    fn all_k_subsets_reconstruct() {
        let mut rng = rng_from_seed(7);
        for (k, n) in [(2usize, 3usize), (3, 5), (4, 6)] {
            let secret = Fr::rand(&mut rng);
            let shares = split(secret, k, n, &mut rng).unwrap();
            for combo in super::combinations(&shares, k) {
                assert_eq!(reconstruct(&combo, k).unwrap(), secret, "k={k} n={n}");
            }
            if k >= 2 {
                for combo in super::combinations(&shares, k - 1) {
                    // k-1 shares interpolate a polynomial of degree k-2, which
                    // hits the true secret only with negligible probability.
                    let wrong = reconstruct(&combo, k - 1).unwrap();
                    assert_ne!(wrong, secret, "k-1 shares must not reveal the secret");
                }
            }
        }
    }

    #[test]
    fn too_few_shares_is_an_error() {
        let mut rng = rng_from_seed(1);
        let shares = split(Fr::rand(&mut rng), 3, 5, &mut rng).unwrap();
        assert!(matches!(
            reconstruct(&shares[..2], 3),
            Err(Error::NotEnoughShares { need: 3, got: 2 })
        ));
    }

    #[test]
    fn rejects_bad_parameters() {
        let mut rng = rng_from_seed(1);
        assert!(split(Fr::rand(&mut rng), 0, 3, &mut rng).is_err());
        assert!(split(Fr::rand(&mut rng), 4, 3, &mut rng).is_err());
        assert!(lagrange_at_zero(&[1, 1]).is_err());
        assert!(lagrange_at_zero(&[0, 1]).is_err());
    }

    #[test]
    fn lagrange_coefficients_sum_to_one() {
        // Interpolating the constant polynomial f(x)=1 at zero must give 1.
        let c = lagrange_at_zero(&[1, 3, 5, 9]).unwrap();
        assert_eq!(c.iter().copied().sum::<Fr>(), Fr::from(1u64));
    }
}
