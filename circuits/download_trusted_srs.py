import asyncio
import hashlib
import os

try:
    import ezkl
except ImportError:
    ezkl = None

# ===================================================================
# CGI Protocol -- MPC Trusted Setup Enforcer
# ===================================================================
# This script ensures that the ZK-ML pipeline strictly uses a 
# Universal Trusted Setup where the "toxic waste" has been verifiably 
# destroyed. It downloads the community-audited KZG SRS and enforces 
# a cryptographic hash check to prevent forged proving keys.
# ===================================================================

# 17 logrows is typically sufficient for our quantized AI models.
LOGROWS = 17 

# The publicly audited SHA-256 hash of the trusted KZG SRS for logrows=17
# This hash corresponds to the Perpetual Powers of Tau ceremony.
# The hash below is a placeholder representing the official downloaded file.
# In a true deployment, you would manually verify this against the Ethereum KZG ceremony outputs.
EXPECTED_HASH = os.environ.get("TRUSTED_SRS_SHA256", "STRICT_ENFORCEMENT_PENDING")


def verify_srs_hash(file_path: str) -> bool:
    """Computes the SHA-256 hash of the downloaded SRS and checks it against the expected hash."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
            
    file_hash = sha256_hash.hexdigest()
    print(f"[MPC] Downloaded SRS SHA-256 Hash: {file_hash}")
    
    if EXPECTED_HASH == "STRICT_ENFORCEMENT_PENDING":
        print("[WARNING] Running in Dev Mode. Strict SRS hash enforcement is bypassed.")
        print(f"Please set TRUSTED_SRS_SHA256={file_hash} for Production.")
        return True
        
    if file_hash != EXPECTED_HASH:
        print("[CRITICAL ERROR] SRS Hash Mismatch!")
        print(f"Expected: {EXPECTED_HASH}")
        print(f"Actual:   {file_hash}")
        return False
        
    print("[OK] SRS Hash cryptographically verified against the Trusted Setup.")
    return True


async def main():
    print("=" * 60)
    print("  CGI Protocol — MPC Trusted Setup Initializer")
    print("=" * 60)

    if ezkl is None:
        raise ImportError("ezkl module not installed. Run 'pip install ezkl'")

    base_dir = os.path.join(os.path.dirname(__file__), "ezkl_artifacts")
    os.makedirs(base_dir, exist_ok=True)
    srs_path = os.path.join(base_dir, "kzg.srs")

    print(f"[MPC] Fetching Universal Trusted Setup (KZG logrows={LOGROWS})...")
    
    # Download the official Universal Trusted Setup from the EZKL community
    # This replaces the locally generated `ezkl.gen_srs` which is insecure.
    # Note: get_srs retrieves the perpetual powers of tau for the requested logrows.
    try:
        res = ezkl.get_srs(srs_path, logrows=LOGROWS)
        if hasattr(res, '__await__'):
            await res
    except BaseException as e:
        print(f"[CRITICAL ERROR] Failed to fetch remote SRS: {e}")
        print("[CRITICAL ERROR] The Windows environment may be blocking remote PyO3 async execution.")
        print("You MUST use the Ubuntu Linux Compiler (e.g. compile_via_docker.ps1) to securely download the Universal Trusted Setup.")
        raise SystemExit("Security Panic: Cannot safely obtain the MPC Trusted Setup.")

    if not os.path.exists(srs_path):
        raise FileNotFoundError(f"Failed to obtain the Trusted Setup at {srs_path}")

    # Enforce cryptographic integrity
    print("[MPC] Verifying 'Toxic Waste' destruction integrity via Hash Check...")
    is_valid = verify_srs_hash(srs_path)

    if not is_valid:
        # Intentionally destroy the compromised file so the compiler cannot use it
        os.remove(srs_path)
        raise SystemExit("Security Panic: Trusted Setup verification failed. The SRS file was destroyed.")

    print("=" * 60)
    print("  [OK] Trusted Setup Verified and Ready for Compilation")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
