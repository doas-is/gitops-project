"""
Static ML Security Analyzer

Three-layer scoring architecture:
  Layer 1: RuleBasedScorer   — deterministic, zero dependencies, always runs
  Layer 2: HFSecurityAnalyzer — fine-tuned GraphCodeBERT/CodeBERT, loads lazily
  Layer 3: EnsembleScorer    — combines L1 + L2 with confidence weighting

Input contract (STRICT):
  - Receives IRPayload only — no raw code, no AST, no strings
  - IR token sequences are structural IDs: "MODULE IMPORT FUNC_DEF CALL DYNAMIC"
  - 45-dim feature vectors are structural metrics only

Output: MLRiskScore with 5 risk dimensions + overall + confidence

Security invariant:
  At no point does any model object receive identifiers, string literals,
  comments, docstrings, or any user-controlled text. Only IR type names
  from a fixed vocabulary of 28 tokens are used.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np

from src.schemas.a2a_schemas import (
    AgentRole, IRPayload, MessageType, MLRiskScore,
    RiskAssessment, create_header,
)

logger = logging.getLogger(__name__)

# IR vocabulary — matches ir_builder.py _AST_TO_IR values
IR_VOCAB = [
    "MODULE", "FUNC_DEF", "CLASS_DEF", "IMPORT", "CALL",
    "BRANCH", "LOOP", "ASSIGN", "RETURN", "RAISE",
    "TRY", "CATCH", "CONTEXT", "GLOBAL", "NONLOCAL",
    "DYNAMIC", "PRIVILEGE", "AWAIT", "YIELD", "LAMBDA",
    "COMPREHENSION", "ASSERT", "DELETE", "IO", "NETWORK",
    "EXPR", "TRUNCATED", "MATCH",
]
_IR_TOKEN_MAP: Dict[str, int] = {t: i for i, t in enumerate(IR_VOCAB)}
_MAX_TOKEN = len(IR_VOCAB)

# Risk weights per IR type (used in feature extraction)
_TOKEN_RISK: Dict[str, float] = {
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


# Feature Extraction

@dataclass
class IRFeatureVector:
    """45-dim structural feature vector — NO semantic content."""
    # 28-dim: normalized token frequency histogram
    token_histogram: np.ndarray
    # 17-dim: structural metrics
    total_nodes: int
    max_depth: int
    avg_children: float
    mean_risk: float
    max_risk: float
    high_risk_ratio: float
    control_flow_ratio: float
    io_ratio: float
    network_ratio: float
    privilege_ratio: float
    dependency_ratio: float
    has_dynamic: bool
    has_global_scope: bool
    edge_count: int
    avg_edge_weight: float
    max_edge_weight: float
    has_privilege: bool

    def to_vector(self) -> np.ndarray:
        """Flatten to 45-dim float32 array."""
        scalar = np.array([
            self.total_nodes / 200.0,
            self.max_depth / 50.0,
            self.avg_children / 10.0,
            self.mean_risk,
            self.max_risk,
            self.high_risk_ratio,
            self.control_flow_ratio,
            self.io_ratio,
            self.network_ratio,
            self.privilege_ratio,
            self.dependency_ratio,
            float(self.has_dynamic),
            float(self.has_global_scope),
            self.edge_count / 500.0,
            self.avg_edge_weight / 2.0,
            self.max_edge_weight / 2.0,
            float(self.has_privilege),
        ], dtype=np.float32)
        return np.concatenate([self.token_histogram, scalar])  # 28 + 17 = 45


def extract_features(ir_payload: IRPayload) -> IRFeatureVector:
    """Extract IRFeatureVector from IRPayload. Pure structural metrics."""
    nodes = ir_payload.ir_nodes
    if not nodes:
        return IRFeatureVector(
            token_histogram=np.zeros(_MAX_TOKEN, dtype=np.float32),
            total_nodes=0, max_depth=0, avg_children=0.0,
            mean_risk=0.0, max_risk=0.0, high_risk_ratio=0.0,
            control_flow_ratio=0.0, io_ratio=0.0, network_ratio=0.0,
            privilege_ratio=0.0, dependency_ratio=0.0,
            has_dynamic=False, has_global_scope=False,
            edge_count=0, avg_edge_weight=0.0, max_edge_weight=0.0,
            has_privilege=False,
        )

    total = len(nodes)

    histogram = np.zeros(_MAX_TOKEN, dtype=np.float32)
    for node in nodes:
        idx = _IR_TOKEN_MAP.get(node.ir_type, 0)
        histogram[idx] += 1
    histogram /= total

    risks = np.array([n.risk_level for n in nodes], dtype=np.float32) / 10.0
    mean_risk = float(np.mean(risks))
    max_risk = float(np.max(risks))
    high_risk_ratio = float(np.sum(risks >= 0.6) / total)

    categories = [n.category for n in nodes]
    cf = categories.count("control_flow") / total
    io = categories.count("io") / total
    net = categories.count("network") / total
    priv = categories.count("privilege") / total
    dep = categories.count("dependency") / total

    ir_types = {n.ir_type for n in nodes}
    has_dynamic = "DYNAMIC" in ir_types
    has_global = "GLOBAL" in ir_types
    has_priv = "PRIVILEGE" in ir_types

    edges = ir_payload.dependency_edges
    if edges:
        weights = [e.weight for e in edges]
        avg_w = float(np.mean(weights))
        max_w = float(np.max(weights))
    else:
        avg_w = max_w = 0.0

    avg_children = sum(len(n.children) for n in nodes) / total

    return IRFeatureVector(
        token_histogram=histogram,
        total_nodes=total,
        max_depth=ir_payload.max_depth,
        avg_children=avg_children,
        mean_risk=mean_risk,
        max_risk=max_risk,
        high_risk_ratio=high_risk_ratio,
        control_flow_ratio=cf,
        io_ratio=io,
        network_ratio=net,
        privilege_ratio=priv,
        dependency_ratio=dep,
        has_dynamic=has_dynamic,
        has_global_scope=has_global,
        edge_count=len(edges),
        avg_edge_weight=avg_w,
        max_edge_weight=max_w,
        has_privilege=has_priv,
    )


def ir_payload_to_sequence(ir_payload: IRPayload) -> str:
    """
    Convert IRPayload to whitespace-separated structural token sequence.
    This is the ONLY input format the ML model receives.

    Example output: "MODULE IMPORT IMPORT FUNC_DEF CALL DYNAMIC NETWORK ASSIGN"
    All tokens come from the fixed 28-item IR_VOCAB — no user-controlled text.
    """
    tokens = [node.ir_type for node in ir_payload.ir_nodes[:300]]
    # Amplify high-signal tokens at sequence end
    if ir_payload.dynamic_eval_count > 0:
        tokens.extend(["DYNAMIC"] * min(ir_payload.dynamic_eval_count, 5))
    if ir_payload.network_call_count > 0:
        tokens.extend(["NETWORK"] * min(ir_payload.network_call_count, 3))
    if ir_payload.privilege_sensitive_count > 0:
        tokens.extend(["PRIVILEGE"] * min(ir_payload.privilege_sensitive_count, 3))
    return " ".join(tokens[:512])


# Layer 1: Rule-Based Scorer

class RuleBasedScorer:
    """
    Deterministic rule engine. Fast, zero-dependency, always available.
    Covers 14 explicit threat patterns across 5 risk dimensions.
    """

    # (condition_key, flag_name, dimension_index, weight)
    # dimensions: 0=structural 1=dep 2=priv 3=backdoor 4=exfil
    RULES = [
        ("has_dynamic",       "PATTERN_DYNAMIC_EVAL",         0, 0.55),
        ("dynamic_eval_count","PATTERN_DYNAMIC_CODE",          0, 0.65),
        ("has_global_scope",  "PATTERN_GLOBAL_SCOPE",          2, 0.45),
        ("has_privilege",     "PATTERN_PRIVILEGE_CALLS",       2, 0.55),
        ("high_risk_density", "PATTERN_HIGH_RISK_DENSITY",     0, 0.45),
        ("complex_structure", "PATTERN_COMPLEX_STRUCTURE",     0, 0.25),
        ("fragmented",        "PATTERN_FRAGMENTED_STRUCTURE",  0, 0.30),
        ("high_dep",          "PATTERN_HIGH_DEPENDENCY",       1, 0.35),
        ("many_imports",      "PATTERN_IMPORT_DENSITY",        1, 0.40),
        ("network_dynamic",   "PATTERN_NETWORK_DYNAMIC",       3, 0.80),
        ("network_eval",      "PATTERN_NETWORK_EVAL",          3, 0.60),
        ("io_network",        "PATTERN_IO_NETWORK",            4, 0.65),
        ("io_loop_network",   "PATTERN_IO_LOOP_NETWORK",       4, 0.75),
        ("io_delete_loop",    "PATTERN_IO_DELETE_LOOP",        0, 0.85),
    ]

    def _conditions(self, fv: IRFeatureVector, ir: IRPayload) -> Dict[str, bool]:
        ir_types = {n.ir_type for n in ir.ir_nodes}
        return {
            "has_dynamic":       fv.has_dynamic,
            "dynamic_eval_count":ir.dynamic_eval_count > 0,
            "has_global_scope":  fv.has_global_scope,
            "has_privilege":     fv.has_privilege,
            "high_risk_density": fv.high_risk_ratio > 0.25,
            "complex_structure": fv.total_nodes > 400 and fv.max_depth > 25,
            "fragmented":        fv.avg_children < 0.5 and fv.total_nodes > 80,
            "high_dep":          fv.dependency_ratio > 0.28,
            "many_imports":      sum(1 for n in ir.ir_nodes if n.ir_type == "IMPORT") > 8,
            "network_dynamic":   fv.network_ratio > 0.03 and fv.has_dynamic,
            "network_eval":      ir.network_call_count > 0 and ir.dynamic_eval_count > 0,
            "io_network":        fv.io_ratio > 0.02 and fv.network_ratio > 0.02,
            "io_loop_network":   (fv.io_ratio > 0.02 and fv.network_ratio > 0.02
                                  and "LOOP" in ir_types),
            "io_delete_loop":    ("IO" in ir_types and "DELETE" in ir_types
                                  and "LOOP" in ir_types),
        }

    def score(self, fv: IRFeatureVector, ir_payload: IRPayload) -> MLRiskScore:
        conds = self._conditions(fv, ir_payload)
        flagged: List[str] = []
        dims = [0.0, 0.0, 0.0, 0.0, 0.0]

        for key, flag, dim, weight in self.RULES:
            if conds.get(key, False):
                flagged.append(flag)
                dims[dim] = min(dims[dim] + weight, 1.0)

        structural, dep, priv, backdoor, exfil = dims

        if ir_payload.privilege_sensitive_count > 5:
            priv = min(priv + 0.4, 1.0)
            flagged.append("PATTERN_PRIVILEGE_ABUSE")

        weights = [0.15, 0.15, 0.25, 0.25, 0.20]
        weighted_avg = sum(s * w for s, w in zip(dims, weights))
        overall = float(np.clip(0.55 * weighted_avg + 0.45 * max(dims), 0.0, 1.0))
        confidence = min(0.72 + len(flagged) * 0.04, 0.92)

        return MLRiskScore(
            structural_anomaly_score=structural,
            dependency_abuse_score=dep,
            privilege_escalation_score=priv,
            obfuscation_score=float(np.clip(structural * 0.8 + float(fv.has_dynamic) * 0.2, 0, 1)),
            backdoor_pattern_score=float(np.clip(max(backdoor, exfil * 0.6), 0, 1)),
            overall_risk=overall,
            confidence=confidence,
            flagged_patterns=list(set(flagged)),
        )


# Layer 2: HuggingFace Model (lazy-loaded)

class HFSecurityAnalyzer:
    """
    Wraps the fine-tuned IRSecurityClassifier for inference.
    Loads lazily. Falls back gracefully if unavailable.
    Input: IR token sequences only — no raw code ever.
    """

    def __init__(
        self,
        checkpoint_dir: str = "/tmp/ir_security_model",
        model_name: str = "microsoft/graphcodebert-base",
        device: str = "auto",
    ) -> None:
        self.checkpoint_dir = checkpoint_dir
        self.model_name = model_name
        self.device = device
        self._classifier = None
        self._available = False
        self._initialized = False

    def _ensure_loaded(self) -> bool:
        if self._initialized:
            return self._available
        try:
            from src.analyzer.model_trainer import IRSecurityClassifier
            self._classifier = IRSecurityClassifier(
                model_name=self.model_name,
                checkpoint_dir=self.checkpoint_dir,
                device=self.device,
            )
            loaded_ft = self._classifier.load_pretrained()
            self._available = True
            self._initialized = True
            status = "fine-tuned checkpoint" if loaded_ft else "base pretrained (not fine-tuned)"
            logger.info("HF analyzer ready: %s [%s]", self.model_name, status)
            return True
        except Exception as e:
            logger.warning("HF analyzer unavailable (%s) — rule-based only", type(e).__name__)
            self._available = False
            self._initialized = True
            return False

    def predict(
        self, ir_payload: IRPayload, fv: IRFeatureVector
    ) -> Optional[Dict[str, float]]:
        if not self._ensure_loaded() or self._classifier is None:
            return None
        try:
            seq = ir_payload_to_sequence(ir_payload)
            vec = fv.to_vector().tolist()
            return self._classifier.predict(seq, vec)
        except Exception as e:
            logger.debug("HF inference error: %s", e)
            return None


# Layer 3: Ensemble

class EnsembleScorer:
    """
    Combines rule-based + HF model scores with adaptive weighting.

    Weights:
      HF available + confident + low disagreement → 40% rules / 60% HF
      HF available + high disagreement            → 70% rules / 30% HF
      HF unavailable                              → 100% rules
    """

    def score(
        self,
        rule_score: MLRiskScore,
        hf_result: Optional[Dict[str, float]],
        fv: IRFeatureVector,
    ) -> MLRiskScore:
        if hf_result is None:
            return MLRiskScore(
                **{k: getattr(rule_score, k) for k in rule_score.model_fields},
                confidence=rule_score.confidence * 0.88,
            )

        hf_risk = hf_result.get("risk_level", 0.0)
        hf_safe = hf_result.get("safe", 0.0)
        hf_risk_adj = hf_risk * (1.0 - hf_safe * 0.4)

        disagreement = abs(rule_score.overall_risk - hf_risk_adj)
        high_disagree = disagreement > 0.35
        hf_confident = hf_safe < 0.3 or hf_risk > 0.6

        if hf_confident and not high_disagree:
            wr, wh = 0.40, 0.60
        elif high_disagree:
            wr, wh = 0.70, 0.30
        else:
            wr, wh = 0.55, 0.45

        def blend(rv: float, key: str) -> float:
            return float(np.clip(wr * rv + wh * hf_result.get(key, rv), 0.0, 1.0))

        structural = blend(rule_score.structural_anomaly_score, "structural_anomaly")
        dep = blend(rule_score.dependency_abuse_score, "dependency_abuse")
        priv = blend(rule_score.privilege_escalation_score, "privilege_escalation")
        backdoor = blend(rule_score.backdoor_pattern_score, "backdoor")
        backdoor = float(np.clip(backdoor + hf_result.get("data_exfiltration", 0.0) * 0.3, 0, 1))
        obf = blend(rule_score.obfuscation_score, "structural_anomaly")
        overall = float(np.clip(wr * rule_score.overall_risk + wh * hf_risk_adj, 0.0, 1.0))

        if high_disagree:
            confidence = rule_score.confidence * 0.70
        elif hf_confident:
            confidence = min(rule_score.confidence * 1.12, 0.96)
        else:
            confidence = rule_score.confidence * 0.90

        flagged = list(rule_score.flagged_patterns)
        if hf_result.get("backdoor", 0.0) > 0.70:
            flagged.append("ML_BACKDOOR_SIGNAL")
        if hf_result.get("privilege_escalation", 0.0) > 0.70:
            flagged.append("ML_PRIVESC_SIGNAL")
        if hf_result.get("data_exfiltration", 0.0) > 0.70:
            flagged.append("ML_EXFIL_SIGNAL")
        if hf_result.get("structural_anomaly", 0.0) > 0.70:
            flagged.append("ML_STRUCTURAL_ANOMALY")
        if high_disagree:
            flagged.append("RULE_ML_DISAGREEMENT")

        return MLRiskScore(
            structural_anomaly_score=structural,
            dependency_abuse_score=dep,
            privilege_escalation_score=priv,
            obfuscation_score=obf,
            backdoor_pattern_score=backdoor,
            overall_risk=overall,
            confidence=float(np.clip(confidence, 0.0, 1.0)),
            flagged_patterns=list(set(flagged)),
        )


# Public Interface

class MLSecurityAnalyzer:
    """
    Public analyzer. Orchestrates all three scoring layers.

    To train:
        python -m src.analyzer.model_trainer --samples 5000
        Checkpoint → /tmp/ir_security_model/

    After training, MLSecurityAnalyzer auto-loads checkpoint on next init.
    Falls back to rule-based if checkpoint not present.
    """

    def __init__(
        self,
        checkpoint_dir: str = "/tmp/ir_security_model",
        model_name: str = "microsoft/graphcodebert-base",
        device: str = "auto",
    ) -> None:
        self._rule_scorer = RuleBasedScorer()
        self._hf = HFSecurityAnalyzer(
            checkpoint_dir=checkpoint_dir,
            model_name=model_name,
            device=device,
        )
        self._ensemble = EnsembleScorer()
        self._times: List[float] = []

    def analyze(self, ir_payload: IRPayload) -> MLRiskScore:
        t0 = time.perf_counter()
        fv = extract_features(ir_payload)
        rule_score = self._rule_scorer.score(fv, ir_payload)
        hf_result = self._hf.predict(ir_payload, fv)
        score = self._ensemble.score(rule_score, hf_result, fv)
        self._times.append(time.perf_counter() - t0)
        return score

    def analyze_batch(
        self, ir_payloads: List[IRPayload], task_id: str
    ) -> RiskAssessment:
        header = create_header(
            MessageType.RISK_ASSESSMENT,
            AgentRole.ML_ANALYZER,
            AgentRole.POLICY_ENGINE,
            task_id,
        )
        if not ir_payloads:
            return RiskAssessment(
                header=header, task_id=task_id, file_scores=[],
                aggregate_risk=0.0, high_risk_file_count=0, total_files=0,
                circular_dependency_count=0, external_dependency_count=0,
                privileged_api_count=0, total_ir_nodes=0, anomalous_pattern_count=0,
            )

        file_scores = [self.analyze(ir) for ir in ir_payloads]
        risks = [s.overall_risk for s in file_scores]
        aggregate_risk = float(np.percentile(risks, 90))
        high_risk_count = sum(1 for r in risks if r > 0.70)

        all_patterns: set = set()
        for s in file_scores:
            all_patterns.update(s.flagged_patterns)

        return RiskAssessment(
            header=header,
            task_id=task_id,
            file_scores=file_scores,
            aggregate_risk=aggregate_risk,
            high_risk_file_count=high_risk_count,
            total_files=len(ir_payloads),
            circular_dependency_count=0,
            external_dependency_count=sum(
                1 for ir in ir_payloads
                if any(n.ir_type == "IMPORT" for n in ir.ir_nodes)
            ),
            privileged_api_count=sum(ir.privilege_sensitive_count for ir in ir_payloads),
            total_ir_nodes=sum(ir.total_nodes for ir in ir_payloads),
            anomalous_pattern_count=len(all_patterns),
        )

    def perf_stats(self) -> Dict:
        if not self._times:
            return {}
        ms = [t * 1000 for t in self._times]
        return {
            "n": len(ms),
            "mean_ms": float(np.mean(ms)),
            "p95_ms": float(np.percentile(ms, 95)),
        }


_analyzer: Optional[MLSecurityAnalyzer] = None


def get_analyzer(**kwargs) -> MLSecurityAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = MLSecurityAnalyzer(**kwargs)
    return _analyzer