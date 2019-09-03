# Sharing

Secret Sharing and Inforamtion Disporsal Sharing

Use for example the Shamir implementation

## Example

```rust
use sharing::{ShamirSecretSharing, Sharing};

let data = [1, 2, 3, 4, 5].to_vec();

let sharer = ShamirSecretSharing::new(5, 3, rand::thread_rng());

let shares = sharer.share(data.clone()).unwrap();
// You only need 3 out of the 5 shares to reconstruct
let rec = sharer.recontruct(shares[1..=3].to_vec()).unwrap();

assert_eq!(data, rec);
```
