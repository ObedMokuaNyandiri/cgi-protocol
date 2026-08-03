# Cryptographic Setup Ceremony (MPC)

The CGI Protocol integrates an advanced Zero-Knowledge Machine Learning (ZK-ML) architecture powered by Halo2 and the KZG Commitment Scheme.

To achieve cryptographic soundness, the system relies on a **Universal Trusted Setup** (the Perpetual Powers of Tau). Unlike Groth16, Halo2 KZG does not require a circuit-specific "Phase 2" ceremony. A single universal ceremony is sufficient up to a specific circuit degree ($2^{23}$ rows).

## The "Toxic Waste" Problem
During a Trusted Setup Ceremony, a set of random numbers is generated to compute the Structured Reference String (SRS). If an attacker knows or recovers the original random numbers (the "toxic waste"), they can mathematically forge fake ZK proofs, completely compromising the AI inference verification.

By participating in a Multi-Party Computation (MPC), the toxic waste is passed among many participants. The mathematical property of MPC ensures that **as long as at least one participant honestly destroys their shard of the toxic waste, the entire system is secure.**

## Enforcing the Universal Setup
We enforce the use of a specifically audited Universal SRS file to prevent the compiler from generating or using a compromised local setup.

**Verification Process:**
1. The compiler executes `download_trusted_srs.py`.
2. The script downloads the KZG SRS from the official ignite S3 repository.
3. Before the compiler is allowed to use this SRS, the script computes its `SHA-256` hash.
4. It compares the hash against the globally known, audited hash of the Perpetual Powers of Tau ceremony.
5. If the hash does not perfectly match, the script panics, permanently halts compilation, and physically deletes the compromised file from the disk.

## Action Required for Mainnet
If you are deploying CGI Protocol to Ethereum Mainnet:
1. Identify the specific `.srs` file provided by the EZKL/Ethereum Foundation community.
2. Verify its cryptographic hash against multiple independent blockchain explorers and community announcements.
3. Set the `TRUSTED_SRS_SHA256` environment variable in your production compilation environment to strictly enforce this specific hash constraint.

```bash
export TRUSTED_SRS_SHA256="your_verified_hash_here"
```

If left unset, the script will operate in Dev Mode, downloading the file but allowing compilation to proceed with a warning.
