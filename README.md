# Validate BTC Header

Validation of Bitcoin header chain using zero-knowledge proofs.

This implementation:

* Uses bellpepper, a fork of `bellperson`, which is itself a fork of `bellman`
* Uses Nova, a recursive SNARK that employs folding schemes

The following Bitcoin consensus rules are checked:

* Proof-of-work
* Target re-calculations
* Previous hash in current block
* Median of timestamps

Tests can be run using `cargo`.
