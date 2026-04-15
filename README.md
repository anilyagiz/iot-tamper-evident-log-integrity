# iot-tamper-evident-log-integrity

Tamper-evident IoT log integrity verification with Merkle proofs, adaptive chunking, and reproducible benchmark results.

## Contents
- `paper_cose.tex`: submission-ready LaTeX manuscript for Computers & Security
- `paper.tex`: alternate manuscript draft
- `benchmark.py`: benchmark runner
- `main.py`: entry point for validation and benchmarking
- `integrity_verifier.py`, `merkle_tree.py`, `adaptive_chunking.py`: core implementation
- `log_generator.py`: synthetic IoT workload generator
- `data/`: CSV exports used by the PGFPlots figures

## Reproduce
```bash
python main.py quick
python main.py benchmark
```

## Notes
- The paper uses PGFPlots/TikZ figures sourced from the CSV files in `data/`.
- The manuscript is written for Elsevier's `Computers & Security` format.
