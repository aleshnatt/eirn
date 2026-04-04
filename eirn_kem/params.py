"""
Eirn-KEM Parameter Sets.

Defines parameter configurations for Eirn-512 and Eirn-768,
mirroring the MLWE-based KEM from the Eirn-AKE whitepaper.

In the simulated implementation, these parameters define byte sizes
for keys and ciphertexts. The actual MLWE parameters (n, k, q, eta)
are documented for reference but not used in computation.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class EirnParams:
    """Parameter set for Eirn-KEM."""
    name: str
    
    # MLWE parameters (reference only — not used in simulation)
    n: int        # polynomial degree
    k: int        # module rank
    q: int        # modulus
    eta1: int     # noise parameter (secret/error generation)
    eta2: int     # noise parameter (encryption noise)
    
    # Byte sizes (used in simulation)
    sk_bytes: int       # secret key size
    pk_bytes: int       # public key size
    ct_bytes: int       # ciphertext size
    ss_bytes: int       # shared secret size
    coins_bytes: int    # encapsulation randomness size
    
    # Security level
    nist_level: int


# Eirn-512: NIST Level 1 (equivalent to AES-128)
PARAMS_512 = EirnParams(
    name="Eirn-512",
    n=256, k=2, q=3329, eta1=3, eta2=2,
    sk_bytes=32,
    pk_bytes=800,     # 12-bit packing: k * n * 12/8 + 32 = 800
    ct_bytes=768,     # compressed ciphertext
    ss_bytes=32,      # shared secret = 256 bits
    coins_bytes=32,   # encapsulation coins = 256 bits
    nist_level=1,
)

# Eirn-768: NIST Level 3 (equivalent to AES-192)
PARAMS_768 = EirnParams(
    name="Eirn-768",
    n=256, k=3, q=3329, eta1=2, eta2=2,
    sk_bytes=32,
    pk_bytes=1184,    # 12-bit packing: k * n * 12/8 + 32 = 1184
    ct_bytes=1088,
    ss_bytes=32,
    coins_bytes=32,
    nist_level=3,
)

# Default parameter set
DEFAULT_PARAMS = PARAMS_512
