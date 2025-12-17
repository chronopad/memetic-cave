"""
Genetic Algorithm core (paper-faithful baseline).

Design constraints:
- Fixed chromosome length (== cave size)
- No PE layout logic
- No cave resizing
- Black-box fitness only

This GA is intentionally simple and stable:
- Tournament selection
- Uniform crossover
- Byte-wise mutation
- Elitism
"""

import random
from typing import List, Tuple
from tqdm import trange

from chromosome import apply_chromosome


class GeneticAlgorithm:
    def __init__(
        self,
        *,
        population_size: int,
        chromosome_length: int,
        fitness_oracle,
        encoder,
        mutation_rate: float = 0.01,
        crossover_rate: float = 0.5,
        elite_fraction: float = 0.1,
        tournament_k: int = 3,
        seed: int = 0,
    ):
        assert 0 < elite_fraction < 1
        self.population_size = population_size
        self.chromosome_length = chromosome_length
        self.fitness_oracle = fitness_oracle
        self.encoder = encoder
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.elite_count = max(1, int(population_size * elite_fraction))
        self.tournament_k = tournament_k

        random.seed(seed)

    # ------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------

    def _random_chromosome(self) -> bytes:
        return bytes(random.getrandbits(8) for _ in range(self.chromosome_length))

    def initialize(self) -> List[bytes]:
        return [self._random_chromosome() for _ in range(self.population_size)]

    # ------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------

    def _tournament_select(self, population: List[bytes], scores: List[float]) -> bytes:
        indices = random.sample(range(len(population)), self.tournament_k)
        best = min(indices, key=lambda i: scores[i])  # lower is better
        return population[best]

    # ------------------------------------------------------------
    # Genetic operators
    # ------------------------------------------------------------

    def _crossover(self, a: bytes, b: bytes) -> Tuple[bytes, bytes]:
        if random.random() > self.crossover_rate:
            return a, b
        mask = [random.getrandbits(1) for _ in range(self.chromosome_length)]
        c1 = bytearray(self.chromosome_length)
        c2 = bytearray(self.chromosome_length)
        for i, m in enumerate(mask):
            if m:
                c1[i] = a[i]
                c2[i] = b[i]
            else:
                c1[i] = b[i]
                c2[i] = a[i]
        return bytes(c1), bytes(c2)

    def _mutate(self, c: bytes) -> bytes:
        out = bytearray(c)
        for i in range(len(out)):
            if random.random() < self.mutation_rate:
                out[i] = random.getrandbits(8)
        return bytes(out)

    # ------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------

    def _evaluate(self, population: List[bytes], pe_bytes: bytes, cave_plan) -> List[float]:
        scores = []
        for chrom in population:
            mutated = apply_chromosome(pe_bytes, cave_plan, chrom, self.encoder)
            score = self.fitness_oracle.score(mutated)
            scores.append(score)
        return scores

    # ------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------

    def run(
        self,
        *,
        pe_bytes: bytes,
        cave_plan,
        generations: int,
    ) -> Tuple[bytes, float, bytes]:
        """
        Returns: (best_chromosome, best_score, best_binary)
        """

        population = self.initialize()
        scores = self._evaluate(population, pe_bytes, cave_plan)

        for gen in trange(generations):
            # --- Elitism ---
            elite_indices = sorted(range(len(scores)), key=lambda i: scores[i])[:self.elite_count]
            new_population = [population[i] for i in elite_indices]

            # --- Reproduction ---
            while len(new_population) < self.population_size:
                p1 = self._tournament_select(population, scores)
                p2 = self._tournament_select(population, scores)
                c1, c2 = self._crossover(p1, p2)
                c1 = self._mutate(c1)
                c2 = self._mutate(c2)
                new_population.append(c1)
                if len(new_population) < self.population_size:
                    new_population.append(c2)

            population = new_population
            scores = self._evaluate(population, pe_bytes, cave_plan)

        best_idx = min(range(len(scores)), key=lambda i: scores[i])
        best_chrom = population[best_idx]
        best_score = scores[best_idx]
        best_binary = apply_chromosome(pe_bytes, cave_plan, best_chrom, self.encoder)

        return best_chrom, best_score, best_binary
