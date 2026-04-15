import csv
import json
from pathlib import Path


def write_csv(path: Path, fieldnames, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="ascii") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def main():
    results = json.loads(Path("benchmark_results.json").read_text(encoding="utf-8"))

    ingestion_adaptive = results["ingestion"]["adaptive"]
    ingestion_fixed = results["ingestion"]["fixed"]

    write_csv(
        Path("data/ingestion_adaptive.csv"),
        ["log_count", "logs_per_second", "logs_per_second_std", "time_seconds_mean", "time_seconds_std", "chunk_size_kb"],
        ingestion_adaptive,
    )
    write_csv(
        Path("data/ingestion_fixed.csv"),
        ["log_count", "logs_per_second", "logs_per_second_std", "time_seconds_mean", "time_seconds_std", "chunk_size_kb"],
        ingestion_fixed,
    )

    batch_ver = results["verification"]["batch_verification"]
    write_csv(
        Path("data/verification_batch.csv"),
        ["batch_size", "avg_time_per_entry_ms", "total_time_ms"],
        batch_ver,
    )

    proof_rows = results["proof_generation"]["proof_results"]
    write_csv(
        Path("data/proof_results.csv"),
        ["index", "generation_time_ms", "proof_size_bytes", "proof_length"],
        proof_rows,
    )

    tamper_rows = results["tampering_detection"]
    write_csv(
        Path("data/tampering_detection.csv"),
        [
            "tamper_ratio",
            "actual_tampered",
            "detected_tampered",
            "detection_time_seconds",
            "detection_accuracy",
            "precision",
            "recall",
            "f1_score",
        ],
        tamper_rows,
    )

    hash_algos = results["hash_algorithms"]
    hash_rows = []
    for algo, vals in hash_algos.items():
        hash_rows.append(
            {
                "algorithm": algo,
                "ingestion_rate_logs_per_sec": vals["ingestion_rate_logs_per_sec"],
                "verification_time_ms": vals["verification_time_ms"],
            }
        )
    write_csv(
        Path("data/hash_algorithms.csv"),
        ["algorithm", "ingestion_rate_logs_per_sec", "verification_time_ms"],
        hash_rows,
    )

    memory = results["memory"]
    memory_rows = [
        {"method": "adaptive", "memory_mb": memory["adaptive_chunking_mb"]},
        {"method": "fixed", "memory_mb": memory["fixed_chunking_mb"]},
        {"method": "traditional", "memory_mb": memory["traditional_merkle_mb"]},
    ]
    write_csv(Path("data/memory.csv"), ["method", "memory_mb"], memory_rows)

    stress = results.get("controlled_stress")
    if stress:
        write_csv(
            Path("data/controlled_stress.csv"),
            ["window", "phase", "pressure", "window_logs", "num_batches", "chunk_size_kb"],
            stress["rows"],
        )


if __name__ == "__main__":
    main()
