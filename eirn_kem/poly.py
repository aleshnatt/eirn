"""
Simulated Polynomial Arithmetic.

In the real Eirn-KEM (C implementation), polynomials are elements of
Z_q[X]/(X^n + 1) with NTT-based multiplication. This module provides
a simplified simulation for protocol-level testing.

The polynomial operations here are NOT used in the simulated KEM
(which is hash-based), but are included for completeness and to 
demonstrate the mathematical foundation of MLWE.
"""

from typing import List
from .params import DEFAULT_PARAMS


class Poly:
    """
    Polynomial in Z_q[X]/(X^n + 1).
    
    Coefficients are stored as a list of integers mod q.
    """
    
    def __init__(self, coeffs: List[int] = None, n: int = None, q: int = None):
        self.n = n or DEFAULT_PARAMS.n
        self.q = q or DEFAULT_PARAMS.q
        
        if coeffs is None:
            self.coeffs = [0] * self.n
        else:
            self.coeffs = [c % self.q for c in coeffs]
            # Pad or truncate to n coefficients
            if len(self.coeffs) < self.n:
                self.coeffs.extend([0] * (self.n - len(self.coeffs)))
            elif len(self.coeffs) > self.n:
                self.coeffs = self.coeffs[:self.n]
    
    def __add__(self, other: "Poly") -> "Poly":
        """Polynomial addition mod q."""
        return Poly(
            [(a + b) % self.q for a, b in zip(self.coeffs, other.coeffs)],
            self.n, self.q
        )
    
    def __sub__(self, other: "Poly") -> "Poly":
        """Polynomial subtraction mod q."""
        return Poly(
            [(a - b) % self.q for a, b in zip(self.coeffs, other.coeffs)],
            self.n, self.q
        )
    
    def __mul__(self, other: "Poly") -> "Poly":
        """
        Polynomial multiplication in Z_q[X]/(X^n + 1).
        
        Uses schoolbook multiplication with reduction mod (X^n + 1).
        In production, this would use NTT for O(n log n) complexity.
        """
        result = [0] * self.n
        
        for i in range(self.n):
            for j in range(self.n):
                idx = i + j
                if idx < self.n:
                    result[idx] = (result[idx] + self.coeffs[i] * other.coeffs[j]) % self.q
                else:
                    # Reduction: X^n ≡ -1 mod (X^n + 1)
                    result[idx - self.n] = (
                        result[idx - self.n] - self.coeffs[i] * other.coeffs[j]
                    ) % self.q
        
        return Poly(result, self.n, self.q)
    
    def __eq__(self, other: "Poly") -> bool:
        return self.coeffs == other.coeffs
    
    def __repr__(self) -> str:
        nonzero = [(i, c) for i, c in enumerate(self.coeffs) if c != 0]
        if not nonzero:
            return "Poly(0)"
        terms = [f"{c}·x^{i}" if i > 0 else str(c) for i, c in nonzero[:5]]
        suffix = " + ..." if len(nonzero) > 5 else ""
        return f"Poly({' + '.join(terms)}{suffix})"
    
    @classmethod
    def random(cls, n: int = None, q: int = None) -> "Poly":
        """Generate a random polynomial with uniform coefficients."""
        import os
        n = n or DEFAULT_PARAMS.n
        q = q or DEFAULT_PARAMS.q
        coeffs = [int.from_bytes(os.urandom(2), "big") % q for _ in range(n)]
        return cls(coeffs, n, q)
    
    @classmethod
    def small(cls, eta: int, n: int = None, q: int = None) -> "Poly":
        """
        Generate a small polynomial with coefficients in [-eta, eta].
        Used for secret/error sampling in MLWE.
        """
        import os
        n = n or DEFAULT_PARAMS.n
        q = q or DEFAULT_PARAMS.q
        coeffs = []
        for _ in range(n):
            c = int.from_bytes(os.urandom(1), "big") % (2 * eta + 1) - eta
            coeffs.append(c % q)
        return cls(coeffs, n, q)
