"""
Fine-Tuning Pipeline: GraphCodeBERT / CodeBERT for IR Security Classification

Architecture:
  Pretrained CodeBERT encoder (frozen or partially frozen)
  → CLS token embedding (768-dim)
  → Concat with 45-dim hand-crafted feature vector
  → Multi-layer classifier head
  → 5 sigmoid outputs (multi-label risk dimensions)
  → 1 sigmoid output (overall risk regression)

Training strategy:
  Phase 1: Freeze encoder, train classifier head only (10 epochs, fast)
  Phase 2: Unfreeze top 3 encoder layers, fine-tune end-to-end (5 epochs, slow)

Input: IR token sequence (structural tokens only — NO code, NO identifiers)
  e.g. "MODULE IMPORT IMPORT FUNC_DEF CALL DYNAMIC NETWORK ASSIGN RETURN"

Labels (multi-label binary):
  [structural_anomaly, dependency_abuse, privilege_escalation,
   backdoor, data_exfiltration, safe]
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# Label names — these map to MLRiskScore dimensions
LABEL_NAMES = [
    "structural_anomaly",
    "dependency_abuse",
    "privilege_escalation",
    "backdoor",
    "data_exfiltration",
    "safe",
]

FEATURE_DIM = 45        # hand-crafted feature vector dimension
EMBEDDING_DIM = 768     # CodeBERT CLS embedding
COMBINED_DIM = FEATURE_DIM + EMBEDDING_DIM   # 813
NUM_LABELS = 6


# ─────────────────────────────────────────────────────────────────
# Dataset
# ─────────────────────────────────────────────────────────────────

class IRSecurityDataset:
    """
    PyTorch Dataset wrapping IR token sequences + feature vectors.

    Each item:
      input_ids:       tokenized IR sequence (max 128 tokens)
      attention_mask:  padding mask
      feature_vector:  45-dim structural feature array
      labels:          6-dim float32 (multi-label)
      risk_level:      float32 scalar (regression)
    """

    def __init__(
        self,
        samples: List,
        tokenizer,
        max_length: int = 128,
    ) -> None:
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict:
        import torch
        s = self.samples[idx]

        encoding = self.tokenizer(
            s.ir_sequence,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "feature_vector": torch.tensor(s.feature_vector, dtype=torch.float32),
            "labels": torch.tensor(s.labels, dtype=torch.float32),
            "risk_level": torch.tensor(s.risk_level, dtype=torch.float32),
        }


# ─────────────────────────────────────────────────────────────────
# Model
# ─────────────────────────────────────────────────────────────────

class IRSecurityClassifier:
    """
    CodeBERT + classifier head for IR security analysis.

    Architecture (as PyTorch module):

    ┌─────────────────────────────────────────────────┐
    │  Input: IR token sequence (max 128 tokens)       │
    │         + 45-dim feature vector                  │
    └───────────────────┬─────────────────────────────┘
                        │
    ┌───────────────────▼─────────────────────────────┐
    │  microsoft/graphcodebert-base                    │
    │  (or microsoft/codebert-base as fallback)        │
    │  → CLS token: 768-dim embedding                  │
    └───────────────────┬─────────────────────────────┘
                        │
    ┌───────────────────▼─────────────────────────────┐
    │  Concat: [CLS_768 || features_45] = 813-dim      │
    └───────────────────┬─────────────────────────────┘
                        │
    ┌───────────────────▼─────────────────────────────┐
    │  Classifier Head:                                │
    │    Linear(813 → 512) + GELU + Dropout(0.3)      │
    │    Linear(512 → 256) + GELU + Dropout(0.2)      │
    │    Linear(256 → 128) + GELU                     │
    │    ├── Linear(128 → 6)  + Sigmoid  [labels]     │
    │    └── Linear(128 → 1)  + Sigmoid  [risk_level] │
    └─────────────────────────────────────────────────┘

    Loss:
      L_label    = BCEWithLogitsLoss (multi-label)
      L_risk     = MSELoss (regression)
      L_total    = 0.7 * L_label + 0.3 * L_risk
    """

    def __init__(
        self,
        model_name: str = "microsoft/graphcodebert-base",
        fallback_model: str = "microsoft/codebert-base",
        device: str = "auto",
        checkpoint_dir: str = "/tmp/ir_security_model",
    ) -> None:
        self.model_name = model_name
        self.fallback_model = fallback_model
        self.checkpoint_dir = checkpoint_dir
        self._model = None
        self._tokenizer = None
        self._initialized = False

        # Auto-detect device
        if device == "auto":
            try:
                import torch
                self.device = "cuda" if torch.cuda.is_available() else "cpu"
            except ImportError:
                self.device = "cpu"
        else:
            self.device = device

    def _build_model(self):
        """Build the full classifier architecture as a PyTorch module."""
        import torch
        import torch.nn as nn
        from transformers import AutoModel

        class _ClassifierHead(nn.Module):
            def __init__(self, input_dim: int, num_labels: int) -> None:
                super().__init__()
                self.shared = nn.Sequential(
                    nn.Linear(input_dim, 512),
                    nn.GELU(),
                    nn.Dropout(0.3),
                    nn.Linear(512, 256),
                    nn.GELU(),
                    nn.Dropout(0.2),
                    nn.Linear(256, 128),
                    nn.GELU(),
                )
                self.label_head = nn.Linear(128, num_labels)
                self.risk_head = nn.Linear(128, 1)

            def forward(self, x):
                shared = self.shared(x)
                labels = torch.sigmoid(self.label_head(shared))
                risk = torch.sigmoid(self.risk_head(shared)).squeeze(-1)
                return labels, risk

        class _FullModel(nn.Module):
            def __init__(
                self,
                encoder,
                feature_dim: int,
                embedding_dim: int,
                num_labels: int,
            ) -> None:
                super().__init__()
                self.encoder = encoder
                self.head = _ClassifierHead(feature_dim + embedding_dim, num_labels)

            def forward(self, input_ids, attention_mask, feature_vector):
                outputs = self.encoder(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                )
                # CLS token embedding
                cls_emb = outputs.last_hidden_state[:, 0, :]
                # Concat with hand-crafted features
                combined = torch.cat([cls_emb, feature_vector], dim=-1)
                labels, risk = self.head(combined)
                return labels, risk

        # Load encoder — try GraphCodeBERT first
        try:
            encoder = AutoModel.from_pretrained(self.model_name)
            logger.info("Loaded encoder: %s", self.model_name)
        except Exception as e:
            logger.warning("GraphCodeBERT unavailable (%s), falling back to %s",
                           type(e).__name__, self.fallback_model)
            encoder = AutoModel.from_pretrained(self.fallback_model)
            self.model_name = self.fallback_model

        model = _FullModel(
            encoder=encoder,
            feature_dim=FEATURE_DIM,
            embedding_dim=EMBEDDING_DIM,
            num_labels=NUM_LABELS,
        )
        return model.to(self.device)

    def load_pretrained(self) -> bool:
        """
        Load from checkpoint if exists, else download base model.
        Returns True if a fine-tuned checkpoint was loaded.
        """
        try:
            from transformers import AutoTokenizer
            import torch

            ckpt_path = Path(self.checkpoint_dir)

            # Check for fine-tuned checkpoint
            if (ckpt_path / "model.pt").exists():
                logger.info("Loading fine-tuned checkpoint from %s", self.checkpoint_dir)
                self._tokenizer = AutoTokenizer.from_pretrained(
                    str(ckpt_path / "tokenizer")
                )
                self._model = self._build_model()
                state = torch.load(
                    ckpt_path / "model.pt",
                    map_location=self.device,
                )
                self._model.load_state_dict(state)
                self._model.eval()
                self._initialized = True
                logger.info("Fine-tuned checkpoint loaded successfully")
                return True
            else:
                # Load base pretrained only
                logger.info("No checkpoint found at %s, loading base model: %s",
                            self.checkpoint_dir, self.model_name)
                try:
                    self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                except Exception:
                    self._tokenizer = AutoTokenizer.from_pretrained(self.fallback_model)
                self._model = self._build_model()
                self._model.eval()
                self._initialized = True
                return False

        except Exception as e:
            logger.warning("Model loading failed: %s — will use rule-based only", e)
            self._initialized = True
            return False

    def train(
        self,
        train_samples: List,
        val_samples: List,
        epochs_phase1: int = 10,
        epochs_phase2: int = 5,
        batch_size: int = 32,
        lr_phase1: float = 3e-4,
        lr_phase2: float = 2e-5,
        save_dir: Optional[str] = None,
    ) -> Dict[str, List[float]]:
        """
        Fine-tune in two phases:

        Phase 1 — Frozen encoder, train head only
          - Fast convergence on task-specific patterns
          - High LR (3e-4), more epochs

        Phase 2 — Unfreeze top 3 encoder layers
          - Subtle domain adaptation
          - Low LR (2e-5), fewer epochs, careful not to catastrophically forget
        """
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader

        if self._tokenizer is None:
            self.load_pretrained()

        save_dir = save_dir or self.checkpoint_dir
        Path(save_dir).mkdir(parents=True, exist_ok=True)

        train_ds = IRSecurityDataset(train_samples, self._tokenizer)
        val_ds = IRSecurityDataset(val_samples, self._tokenizer)
        train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=0)
        val_loader = DataLoader(val_ds, batch_size=batch_size * 2, shuffle=False, num_workers=0)

        history: Dict[str, List[float]] = {
            "train_loss": [], "val_loss": [],
            "val_label_f1": [], "val_risk_mae": [],
        }

        label_loss_fn = nn.BCELoss()
        risk_loss_fn = nn.MSELoss()

        def run_epoch(loader, optimizer, train_mode: bool) -> Tuple[float, float, float]:
            if train_mode:
                self._model.train()
            else:
                self._model.eval()

            total_loss = 0.0
            all_preds, all_targets = [], []
            all_risk_preds, all_risk_targets = [], []

            ctx = torch.enable_grad() if train_mode else torch.no_grad()
            with ctx:
                for batch in loader:
                    input_ids = batch["input_ids"].to(self.device)
                    attention_mask = batch["attention_mask"].to(self.device)
                    feature_vector = batch["feature_vector"].to(self.device)
                    labels = batch["labels"].to(self.device)
                    risk = batch["risk_level"].to(self.device)

                    pred_labels, pred_risk = self._model(
                        input_ids, attention_mask, feature_vector
                    )

                    l_label = label_loss_fn(pred_labels, labels)
                    l_risk = risk_loss_fn(pred_risk, risk)
                    loss = 0.7 * l_label + 0.3 * l_risk

                    if train_mode:
                        optimizer.zero_grad()
                        loss.backward()
                        torch.nn.utils.clip_grad_norm_(self._model.parameters(), 1.0)
                        optimizer.step()

                    total_loss += loss.item()
                    all_preds.append(pred_labels.detach().cpu().numpy())
                    all_targets.append(labels.detach().cpu().numpy())
                    all_risk_preds.append(pred_risk.detach().cpu().numpy())
                    all_risk_targets.append(risk.detach().cpu().numpy())

            avg_loss = total_loss / len(loader)

            # F1 for label prediction (threshold 0.5)
            preds_np = np.vstack(all_preds)
            targets_np = np.vstack(all_targets)
            binary_preds = (preds_np >= 0.5).astype(float)
            f1 = _f1_multilabel(binary_preds, targets_np)

            # MAE for risk
            risk_preds_np = np.concatenate(all_risk_preds)
            risk_targets_np = np.concatenate(all_risk_targets)
            mae = float(np.mean(np.abs(risk_preds_np - risk_targets_np)))

            return avg_loss, f1, mae

        # ── Phase 1: Freeze encoder ──────────────────────────────
        logger.info("Phase 1: Training classifier head (encoder frozen)...")
        for param in self._model.encoder.parameters():
            param.requires_grad = False
        for param in self._model.head.parameters():
            param.requires_grad = True

        optimizer = torch.optim.AdamW(
            filter(lambda p: p.requires_grad, self._model.parameters()),
            lr=lr_phase1,
            weight_decay=0.01,
        )
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=epochs_phase1
        )

        for epoch in range(epochs_phase1):
            t0 = time.time()
            train_loss, _, _ = run_epoch(train_loader, optimizer, train_mode=True)
            val_loss, val_f1, val_mae = run_epoch(val_loader, optimizer, train_mode=False)
            scheduler.step()

            history["train_loss"].append(train_loss)
            history["val_loss"].append(val_loss)
            history["val_label_f1"].append(val_f1)
            history["val_risk_mae"].append(val_mae)

            logger.info(
                "[P1 E%02d/%02d] train_loss=%.4f  val_loss=%.4f  "
                "val_f1=%.3f  val_mae=%.3f  (%.1fs)",
                epoch + 1, epochs_phase1,
                train_loss, val_loss, val_f1, val_mae,
                time.time() - t0,
            )

        # ── Phase 2: Unfreeze top 3 encoder layers ───────────────
        logger.info("Phase 2: Fine-tuning with top encoder layers unfrozen...")
        # Unfreeze only top 3 transformer layers
        for name, param in self._model.encoder.named_parameters():
            # encoder.encoder.layer.{N} — unfreeze layers 9, 10, 11
            if any(f"layer.{i}" in name for i in [9, 10, 11]):
                param.requires_grad = True
            # Also unfreeze pooler
            if "pooler" in name:
                param.requires_grad = True

        optimizer = torch.optim.AdamW([
            {"params": filter(lambda p: p.requires_grad,
                              self._model.encoder.parameters()), "lr": lr_phase2},
            {"params": self._model.head.parameters(), "lr": lr_phase2 * 10},
        ], weight_decay=0.01)

        scheduler = torch.optim.lr_scheduler.LinearLR(
            optimizer, start_factor=1.0, end_factor=0.1, total_iters=epochs_phase2
        )

        best_val_loss = float("inf")
        for epoch in range(epochs_phase2):
            t0 = time.time()
            train_loss, _, _ = run_epoch(train_loader, optimizer, train_mode=True)
            val_loss, val_f1, val_mae = run_epoch(val_loader, optimizer, train_mode=False)
            scheduler.step()

            history["train_loss"].append(train_loss)
            history["val_loss"].append(val_loss)
            history["val_label_f1"].append(val_f1)
            history["val_risk_mae"].append(val_mae)

            logger.info(
                "[P2 E%02d/%02d] train_loss=%.4f  val_loss=%.4f  "
                "val_f1=%.3f  val_mae=%.3f  (%.1fs)",
                epoch + 1, epochs_phase2,
                train_loss, val_loss, val_f1, val_mae,
                time.time() - t0,
            )

            # Save best checkpoint
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                self._save_checkpoint(save_dir)
                logger.info("  ✓ New best checkpoint saved (val_loss=%.4f)", val_loss)

        logger.info("Training complete. Best val_loss=%.4f", best_val_loss)
        return history

    def _save_checkpoint(self, save_dir: str) -> None:
        """Save model weights and tokenizer."""
        import torch
        p = Path(save_dir)
        p.mkdir(parents=True, exist_ok=True)
        torch.save(self._model.state_dict(), p / "model.pt")
        self._tokenizer.save_pretrained(str(p / "tokenizer"))
        meta = {
            "model_name": self.model_name,
            "label_names": LABEL_NAMES,
            "feature_dim": FEATURE_DIM,
        }
        (p / "meta.json").write_text(json.dumps(meta, indent=2))

    @torch.no_grad()
    def predict(
        self,
        ir_sequence: str,
        feature_vector: List[float],
    ) -> Dict[str, float]:
        """
        Run inference on a single IR sequence.
        Returns dict of {label_name: score, "risk_level": float}.
        """
        import torch

        if not self._initialized:
            self.load_pretrained()

        if self._model is None:
            return {name: 0.0 for name in LABEL_NAMES + ["risk_level"]}

        self._model.eval()
        encoding = self._tokenizer(
            ir_sequence,
            max_length=128,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        input_ids = encoding["input_ids"].to(self.device)
        attention_mask = encoding["attention_mask"].to(self.device)
        fv = torch.tensor([feature_vector], dtype=torch.float32).to(self.device)

        pred_labels, pred_risk = self._model(input_ids, attention_mask, fv)
        label_scores = pred_labels[0].cpu().numpy().tolist()
        risk_score = float(pred_risk[0].cpu().numpy())

        result = {name: float(score) for name, score in zip(LABEL_NAMES, label_scores)}
        result["risk_level"] = risk_score
        return result


def _f1_multilabel(preds: np.ndarray, targets: np.ndarray) -> float:
    """Macro F1 for multi-label classification."""
    f1s = []
    for i in range(preds.shape[1]):
        tp = float(np.sum((preds[:, i] == 1) & (targets[:, i] >= 0.5)))
        fp = float(np.sum((preds[:, i] == 1) & (targets[:, i] < 0.5)))
        fn = float(np.sum((preds[:, i] == 0) & (targets[:, i] >= 0.5)))
        prec = tp / (tp + fp + 1e-9)
        rec = tp / (tp + fn + 1e-9)
        f1s.append(2 * prec * rec / (prec + rec + 1e-9))
    return float(np.mean(f1s))


# ─────────────────────────────────────────────────────────────────
# CLI: python -m src.analyzer.model_trainer
# ─────────────────────────────────────────────────────────────────

def main() -> None:
    """End-to-end training run."""
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    parser = argparse.ArgumentParser(description="Train IR Security Classifier")
    parser.add_argument("--samples", type=int, default=5000)
    parser.add_argument("--epochs-p1", type=int, default=10)
    parser.add_argument("--epochs-p2", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--model", default="microsoft/graphcodebert-base")
    parser.add_argument("--save-dir", default="/tmp/ir_security_model")
    parser.add_argument("--device", default="auto")
    args = parser.parse_args()

    from src.analyzer.training_data import generate_dataset, split_dataset, print_stats

    logger.info("=== Generating synthetic IR training dataset ===")
    all_samples = generate_dataset(n_samples=args.samples, seed=42)
    print_stats(all_samples)
    train, val, test = split_dataset(all_samples)
    logger.info("Split: train=%d  val=%d  test=%d", len(train), len(val), len(test))

    logger.info("\n=== Initializing model: %s ===", args.model)
    classifier = IRSecurityClassifier(
        model_name=args.model,
        device=args.device,
        checkpoint_dir=args.save_dir,
    )
    classifier.load_pretrained()

    logger.info("\n=== Fine-tuning ===")
    history = classifier.train(
        train_samples=train,
        val_samples=val,
        epochs_phase1=args.epochs_p1,
        epochs_phase2=args.epochs_p2,
        batch_size=args.batch_size,
        save_dir=args.save_dir,
    )

    # Evaluation on test set
    logger.info("\n=== Evaluating on test set ===")
    import torch
    from torch.utils.data import DataLoader

    test_ds = IRSecurityDataset(test, classifier._tokenizer)
    test_loader = DataLoader(test_ds, batch_size=64, shuffle=False)

    all_preds, all_targets = [], []
    all_risk_preds, all_risk_targets = [], []

    classifier._model.eval()
    with torch.no_grad():
        for batch in test_loader:
            input_ids = batch["input_ids"].to(classifier.device)
            attention_mask = batch["attention_mask"].to(classifier.device)
            fv = batch["feature_vector"].to(classifier.device)
            pred_labels, pred_risk = classifier._model(input_ids, attention_mask, fv)
            all_preds.append(pred_labels.cpu().numpy())
            all_targets.append(batch["labels"].numpy())
            all_risk_preds.append(pred_risk.cpu().numpy())
            all_risk_targets.append(batch["risk_level"].numpy())

    preds_np = np.vstack(all_preds)
    targets_np = np.vstack(all_targets)
    binary_preds = (preds_np >= 0.5).astype(float)
    macro_f1 = _f1_multilabel(binary_preds, targets_np)

    risk_preds_np = np.concatenate(all_risk_preds)
    risk_targets_np = np.concatenate(all_risk_targets)
    mae = float(np.mean(np.abs(risk_preds_np - risk_targets_np)))

    logger.info("Test macro F1:      %.4f", macro_f1)
    logger.info("Test risk MAE:      %.4f", mae)
    logger.info("\nPer-label accuracy:")
    for i, name in enumerate(LABEL_NAMES):
        acc = float(np.mean(binary_preds[:, i] == (targets_np[:, i] >= 0.5)))
        logger.info("  %-25s %.3f", name, acc)

    logger.info("\nModel saved to: %s", args.save_dir)


if __name__ == "__main__":
    main()