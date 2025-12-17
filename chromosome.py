from typing import Optional

class ChromosomeEncoder:
    """
    Maps GA chromosome -> exact cave-sized bytes.
    """

    def __init__(self, *, alphabet: Optional[bytes] = None):
        self.alphabet = alphabet

    def encode(self, chromosome: bytes, cave_size: int) -> bytes:
        if len(chromosome) != cave_size:
            raise ValueError("Chromosome length mismatch")

        if self.alphabet is None:
            return chromosome

        out = bytearray(cave_size)
        a = self.alphabet
        m = len(a)
        for i, b in enumerate(chromosome):
            out[i] = a[b % m]
        return bytes(out)


def apply_chromosome(pe_bytes, cave_plan, chromosome, encoder):
    """
    The ONLY allowed write path for GA.
    """
    encoded = encoder.encode(chromosome, cave_plan.chromosome_length)
    return cave_plan.write_chromosome(pe_bytes, encoded)
