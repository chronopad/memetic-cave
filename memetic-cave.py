# Imports (optimizer, code caver, blackbox interface)
import sys
from contiguous_code_cave_allocator import ContiguousCodeCaveAllocator
from chromosome import ChromosomeEncoder
from fitness import FitnessOracle
from detector_ember import EmberDetector

from genetic_algorithm import GeneticAlgorithm


sha256 = sys.argv[1]
FILE_INPUT = f"malwares/{sha256}.exe"
FILE_OUTPUT = f"patched/{sha256}.exe"

with open(FILE_INPUT, "rb") as f:
    pe_bytes = f.read()

allocator = ContiguousCodeCaveAllocator(pe_bytes)
patched, cave_plan = allocator.allocate(payload_len=4096)

detector = EmberDetector("weight-ember.txt")
oracle = FitnessOracle(detector.score)
encoder = ChromosomeEncoder()
print("Initial score:", oracle.score(patched))

ga = GeneticAlgorithm(
    population_size=30,
    chromosome_length=cave_plan.chromosome_length,
    fitness_oracle=oracle,
    encoder=encoder,
    mutation_rate=0.01,
    crossover_rate=0.5,
    elite_fraction=0.1,
    tournament_k=3,
    seed=0,
)

best_chrom, best_score, best_binary = ga.run(
    pe_bytes=patched,      # IMPORTANT: base binary with empty cave
    cave_plan=cave_plan,
    generations=20,
)

with open(FILE_OUTPUT, "wb") as f:
    f.write(best_binary)
print("Best score:", best_score)
