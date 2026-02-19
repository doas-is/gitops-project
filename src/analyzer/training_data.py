"""
Security Training Dataset Generator

Generates synthetic labeled IR sequences for fine-tuning CodeBERT
on code security classification.

Labels (multi-label, one per risk dimension):
  0: structural_anomaly   — obfuscation, abnormal complexity
  1: dependency_abuse     — typosquatting, dep confusion, supply chain
  2: privilege_escalation — GLOBAL scope abuse, ctypes, os.setuid
  3: backdoor             — network + dynamic eval, C2 patterns
  4: data_exfiltration    — file read + network write
  5: safe                 — no meaningful risk

Training samples are IR token sequences (NOT code) of the form:
  "MODULE IMPORT IMPORT FUNC_DEF CALL DYNAMIC NETWORK ASSIGN RETURN"

Each sample has:
  - ir_sequence: space-separated IR type tokens
  - feature_vector: 45-dim float array
  - labels: 6-dim binary float vector (multi-label)
  - risk_level: float 0-1 (regression target)
  - threat_class: primary threat category string
"""
from __future__ import annotations

import json
import random
import secrets
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple
import numpy as np

# IR vocabulary (must match ir_builder.py)
IR_VOCAB = [
    "MODULE", "FUNC_DEF", "CLASS_DEF", "IMPORT", "CALL",
    "BRANCH", "LOOP", "ASSIGN", "RETURN", "RAISE",
    "TRY", "CATCH", "CONTEXT", "GLOBAL", "NONLOCAL",
    "DYNAMIC", "PRIVILEGE", "AWAIT", "YIELD", "LAMBDA",
    "COMPREHENSION", "ASSERT", "DELETE", "IO", "NETWORK",
    "EXPR", "TRUNCATED", "MATCH",
]

# Token risk weights (base, used for synthetic generation)
TOKEN_RISK: Dict[str, float] = {
    "MODULE": 0.0, "FUNC_DEF": 0.1, "CLASS_DEF": 0.1,
    "IMPORT": 0.2, "CALL": 0.2, "BRANCH": 0.1, "LOOP": 0.1,
    "ASSIGN": 0.0, "RETURN": 0.0, "RAISE": 0.2,
    "TRY": 0.1, "CATCH": 0.1, "CONTEXT": 0.1,
    "GLOBAL": 0.6, "NONLOCAL": 0.4,
    "DYNAMIC": 0.9, "PRIVILEGE": 0.8,
    "AWAIT": 0.1, "YIELD": 0.1, "LAMBDA": 0.3,
    "COMPREHENSION": 0.1, "ASSERT": 0.0,
    "DELETE": 0.3, "IO": 0.4, "NETWORK": 0.5,
    "EXPR": 0.0, "TRUNCATED": 0.1, "MATCH": 0.1,
}

# Threat class → required token patterns
THREAT_PATTERNS: Dict[str, Dict] = {
    "backdoor": {
        "required": ["DYNAMIC", "NETWORK"],
        "likely": ["IMPORT", "CALL", "ASSIGN", "FUNC_DEF"],
        "risk": 0.92,
        "labels": [0.3, 0.3, 0.4, 1.0, 0.5, 0.0],
        "description": "C2/backdoor: dynamic eval + network exfil",
    },
    "data_exfiltration": {
        "required": ["IO", "NETWORK"],
        "likely": ["IMPORT", "CALL", "LOOP", "ASSIGN"],
        "risk": 0.78,
        "labels": [0.2, 0.2, 0.2, 0.3, 1.0, 0.0],
        "description": "Read local data, send over network",
    },
    "privilege_escalation": {
        "required": ["GLOBAL", "PRIVILEGE"],
        "likely": ["CALL", "IMPORT", "ASSIGN", "FUNC_DEF"],
        "risk": 0.85,
        "labels": [0.3, 0.2, 1.0, 0.3, 0.2, 0.0],
        "description": "Global scope manipulation, setuid, ctypes abuse",
    },
    "supply_chain": {
        "required": ["IMPORT", "CALL"],
        "likely": ["ASSIGN", "FUNC_DEF", "NETWORK"],
        "risk": 0.71,
        "labels": [0.2, 1.0, 0.4, 0.5, 0.3, 0.0],
        "description": "Malicious package: import + phone home",
        "high_import_count": True,
    },
    "obfuscation": {
        "required": ["DYNAMIC", "LAMBDA"],
        "likely": ["COMPREHENSION", "ASSIGN", "CALL"],
        "risk": 0.80,
        "labels": [1.0, 0.3, 0.2, 0.5, 0.3, 0.0],
        "description": "Obfuscated execution via eval/lambda chains",
    },
    "cryptominer": {
        "required": ["LOOP", "CALL", "NETWORK"],
        "likely": ["IMPORT", "ASSIGN", "FUNC_DEF", "AWAIT"],
        "risk": 0.68,
        "labels": [0.2, 0.3, 0.2, 0.4, 0.4, 0.0],
        "description": "CPU-intensive loop + network pool connection",
    },
    "credential_theft": {
        "required": ["IO", "ASSIGN"],
        "likely": ["IMPORT", "CALL", "BRANCH", "NETWORK"],
        "risk": 0.82,
        "labels": [0.2, 0.2, 0.3, 0.4, 0.9, 0.0],
        "description": "Read credential files, exfiltrate",
    },
    "ransomware": {
        "required": ["IO", "DELETE", "LOOP"],
        "likely": ["CALL", "IMPORT", "ASSIGN", "BRANCH"],
        "risk": 0.95,
        "labels": [0.5, 0.3, 0.6, 0.7, 0.6, 0.0],
        "description": "Enumerate + encrypt + delete files",
    },
    "process_injection": {
        "required": ["PRIVILEGE", "CALL"],
        "likely": ["IMPORT", "ASSIGN", "DYNAMIC"],
        "risk": 0.90,
        "labels": [0.4, 0.2, 1.0, 0.7, 0.3, 0.0],
        "description": "ctypes/cffi for process memory injection",
    },
    "safe_utility": {
        "required": [],
        "likely": ["FUNC_DEF", "ASSIGN", "RETURN", "BRANCH", "LOOP"],
        "risk": 0.05,
        "labels": [0.0, 0.0, 0.0, 0.0, 0.0, 1.0],
        "description": "Normal utility code",
    },
    "safe_webapi": {
        "required": ["IMPORT", "CALL"],
        "likely": ["FUNC_DEF", "ASSIGN", "RETURN", "BRANCH", "AWAIT"],
        "risk": 0.08,
        "labels": [0.0, 0.0, 0.0, 0.0, 0.0, 1.0],
        "description": "Normal async web API code",
    },
    "safe_dataprocessing": {
        "required": ["LOOP", "ASSIGN"],
        "likely": ["FUNC_DEF", "COMPREHENSION", "RETURN", "IMPORT"],
        "risk": 0.06,
        "labels": [0.0, 0.0, 0.0, 0.0, 0.0, 1.0],
        "description": "Normal data processing code",
    },
}


@dataclass
class TrainingSample:
    ir_sequence: str          # Space-separated IR token types
    feature_vector: List[float]
    labels: List[float]       # 6-dim multi-label
    risk_level: float         # 0-1 regression target
    threat_class: str
    sequence_length: int
    token_counts: Dict[str, int]


def _generate_ir_sequence(
    threat_class: str,
    pattern: Dict,
    length_range: Tuple[int, int] = (20, 150),
) -> List[str]:
    """Generate a plausible IR token sequence for a threat class."""
    rng = random.Random(secrets.randbits(32))
    target_length = rng.randint(*length_range)

    # Start with required tokens
    tokens = list(pattern["required"])

    # Add likely tokens proportionally
    likely = pattern["likely"]
    while len(tokens) < target_length:
        # Weight toward likely tokens
        if rng.random() < 0.7 and likely:
            tokens.append(rng.choice(likely))
        else:
            tokens.append(rng.choice(IR_VOCAB))

    # Shuffle with required tokens peppered throughout
    # (keep required tokens distributed, not clustered at start)
    required = list(pattern["required"])
    rest = [t for t in tokens if t not in required]
    rng.shuffle(rest)

    # Interleave required tokens at random positions
    positions = sorted(rng.sample(range(len(tokens)), min(len(required), len(tokens))))
    for i, pos in enumerate(positions):
        rest.insert(pos, required[i % len(required)])

    # For supply chain: amplify import count
    if pattern.get("high_import_count"):
        extra_imports = ["IMPORT"] * rng.randint(5, 15)
        insert_pts = sorted(rng.sample(range(len(rest)), min(len(extra_imports), len(rest))))
        for i, pt in enumerate(insert_pts):
            rest.insert(pt, extra_imports[i])

    return rest[:target_length]


def _compute_feature_vector(tokens: List[str]) -> List[float]:
    """
    Compute 45-dim feature vector from IR token sequence.
    Matches the structure expected by the classifier head.
    """
    total = len(tokens) if tokens else 1
    counts = {tok: tokens.count(tok) for tok in IR_VOCAB}

    # 28-dim token frequency histogram
    histogram = [counts.get(t, 0) / total for t in IR_VOCAB]

    # 17-dim structural features
    risk_vals = [TOKEN_RISK.get(t, 0.0) for t in tokens]
    mean_risk = float(np.mean(risk_vals))
    max_risk = float(np.max(risk_vals))
    high_risk_ratio = sum(1 for r in risk_vals if r >= 0.6) / total

    structural = [
        total / 200.0,             # normalized length
        min(total / 50.0, 1.0),    # depth proxy
        0.5,                       # avg_children (synthetic)
        mean_risk / 1.0,
        max_risk / 1.0,
        high_risk_ratio,
        counts.get("BRANCH", 0) / total,
        counts.get("IO", 0) / total,
        counts.get("NETWORK", 0) / total,
        counts.get("PRIVILEGE", 0) / total + counts.get("GLOBAL", 0) / total,
        counts.get("IMPORT", 0) / total,
        float("DYNAMIC" in counts and counts["DYNAMIC"] > 0),
        float("GLOBAL" in counts and counts["GLOBAL"] > 0),
        (counts.get("IMPORT", 0) + counts.get("CALL", 0)) / total,  # edge density proxy
        0.5,  # avg edge weight placeholder
        max_risk,
        float("PRIVILEGE" in counts and counts["PRIVILEGE"] > 0),
    ]

    return histogram + structural  # 28 + 17 = 45 dims


def generate_dataset(
    n_samples: int = 5000,
    seed: int = 42,
    class_balance: bool = True,
) -> List[TrainingSample]:
    """
    Generate synthetic labeled training dataset.
    
    Args:
        n_samples: Total samples to generate
        seed: Random seed for reproducibility
        class_balance: Balance threat classes
    """
    random.seed(seed)
    np.random.seed(seed)

    samples = []
    threat_classes = list(THREAT_PATTERNS.keys())

    # Balance: each class gets roughly equal representation
    samples_per_class = n_samples // len(threat_classes)

    for threat_class in threat_classes:
        pattern = THREAT_PATTERNS[threat_class]
        class_samples = samples_per_class if class_balance else random.randint(
            samples_per_class // 2, samples_per_class * 2
        )

        for _ in range(class_samples):
            # Vary sequence length by threat class
            if threat_class.startswith("safe"):
                length_range = (10, 80)
            elif threat_class == "ransomware":
                length_range = (40, 200)
            else:
                length_range = (15, 120)

            tokens = _generate_ir_sequence(threat_class, pattern, length_range)

            # Add noise: occasionally flip some tokens
            noise_rate = random.uniform(0.0, 0.15)
            noisy_tokens = []
            for tok in tokens:
                if random.random() < noise_rate:
                    noisy_tokens.append(random.choice(IR_VOCAB))
                else:
                    noisy_tokens.append(tok)

            fv = _compute_feature_vector(noisy_tokens)

            # Risk level: base + noise
            base_risk = pattern["risk"]
            risk_noise = random.gauss(0, 0.05)
            risk_level = float(np.clip(base_risk + risk_noise, 0.0, 1.0))

            # Labels: base + noise
            labels = [
                float(np.clip(l + random.gauss(0, 0.05), 0.0, 1.0))
                for l in pattern["labels"]
            ]

            ir_sequence = " ".join(noisy_tokens)
            token_counts = {tok: noisy_tokens.count(tok) for tok in set(noisy_tokens)}

            samples.append(TrainingSample(
                ir_sequence=ir_sequence,
                feature_vector=fv,
                labels=labels,
                risk_level=risk_level,
                threat_class=threat_class,
                sequence_length=len(noisy_tokens),
                token_counts=token_counts,
            ))

    # Shuffle
    random.shuffle(samples)
    return samples


def split_dataset(
    samples: List[TrainingSample],
    train_ratio: float = 0.80,
    val_ratio: float = 0.10,
) -> Tuple[List, List, List]:
    """Split into train/val/test."""
    n = len(samples)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)
    return samples[:n_train], samples[n_train:n_train + n_val], samples[n_train + n_val:]


def save_dataset(samples: List[TrainingSample], path: str) -> None:
    """Save as JSONL."""
    with open(path, "w") as f:
        for s in samples:
            f.write(json.dumps(asdict(s)) + "\n")
    print(f"Saved {len(samples)} samples → {path}")


def load_dataset(path: str) -> List[TrainingSample]:
    """Load from JSONL."""
    samples = []
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            samples.append(TrainingSample(**d))
    return samples


def print_stats(samples: List[TrainingSample]) -> None:
    """Print dataset statistics."""
    from collections import Counter
    counts = Counter(s.threat_class for s in samples)
    risks = [s.risk_level for s in samples]
    print(f"\nDataset: {len(samples)} samples")
    print(f"Risk: mean={np.mean(risks):.3f} std={np.std(risks):.3f} "
          f"min={np.min(risks):.3f} max={np.max(risks):.3f}")
    print("\nClass distribution:")
    for cls, cnt in sorted(counts.items(), key=lambda x: -x[1]):
        bar = "█" * (cnt // 10)
        print(f"  {cls:<25} {cnt:>5}  {bar}")


if __name__ == "__main__":
    print("Generating synthetic IR security training dataset...")
    samples = generate_dataset(n_samples=5000, seed=42)
    print_stats(samples)
    train, val, test = split_dataset(samples)
    save_dataset(train, "/tmp/ir_security_train.jsonl")
    save_dataset(val,   "/tmp/ir_security_val.jsonl")
    save_dataset(test,  "/tmp/ir_security_test.jsonl")
    print("\nDone. Files written to /tmp/")