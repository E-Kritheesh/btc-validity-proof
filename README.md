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

**Note:** A few soundness bugs have been found in this implementation of the consensus proofs with respect to field element assignments. These errors are present in the **main** branch. The branch **fix-assignment-bugs** is created to resolve these issues (the work is in progress).  
