import hashlib

class FitnessOracle:
    """
    Black-box detector wrapper with memoization.
    Lower score = better evasion.
    """

    def __init__(self, detector_fn):
        self.detector_fn = detector_fn
        self._cache = {}

    def _key(self, pe_bytes: bytes) -> str:
        return hashlib.sha256(pe_bytes).hexdigest()

    def score(self, pe_bytes: bytes) -> float:
        k = self._key(pe_bytes)
        if k not in self._cache:
            self._cache[k] = float(self.detector_fn(pe_bytes))
        return self._cache[k]

    def delta(self, original_bytes: bytes, mutated_bytes: bytes) -> float:
        return self.score(original_bytes) - self.score(mutated_bytes)
