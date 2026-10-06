"""
self_eval.py
============
Purpose
-------
Evaluate the engine's predicted `risk_level` against ground-truth
labels (dependency_labels.csv) for hackathon scoring / demo purposes.
This module is diagnostic only — it never influences `analyze_all`'s
output and is never required for the pipeline to run.

Inputs
------
- predictions: pd.DataFrame - the analyze_all() output (must contain
  app_id, library, version, risk_level)
- ground_truth: pd.DataFrame - parser.load_ground_truth_labels() output
  (app_id, library, version, ground_truth_risk_level)

Outputs
-------
An `EvaluationReport` dataclass with:
- accuracy: float
- precision_weighted / recall_weighted / f1_weighted: float
- false_positive_rate: float (binary: risky = HIGH/CRITICAL)
- confusion_matrix: pd.DataFrame (labeled, human-readable)
- per_class_report: pd.DataFrame (precision/recall/f1/support per class)
- matched_rows: int
- unmatched_rows: int

Workflow
--------
1. Inner-join predictions to ground truth on (app_id, library, version).
   Rows that don't match either side are reported but excluded from
   metric computation (can't score what has no ground truth).
2. Compute standard multi-class classification metrics via
   scikit-learn (accuracy, weighted precision/recall/F1, confusion
   matrix).
3. Additionally binarize into RISKY (HIGH/CRITICAL) vs NOT_RISKY
   (LOW/MEDIUM) to compute a false positive rate, since FPR is only
   well-defined for a binary "positive" class and "risky vs not" is
   the natural business framing for this domain.
4. Render a neatly formatted text summary via `format_report`.
"""

from __future__ import annotations

import logging

import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    precision_recall_fscore_support,
)

logger = logging.getLogger(__name__)

_RISK_LEVELS_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_RISKY_LEVELS = {"HIGH", "CRITICAL"}


class EvaluationReport:
    """Container for all computed evaluation metrics."""

    def __init__(
        self,
        accuracy: float,
        precision_weighted: float,
        recall_weighted: float,
        f1_weighted: float,
        false_positive_rate: float,
        confusion_df: pd.DataFrame,
        per_class_report: pd.DataFrame,
        matched_rows: int,
        unmatched_rows: int,
    ) -> None:
        self.accuracy = accuracy
        self.precision_weighted = precision_weighted
        self.recall_weighted = recall_weighted
        self.f1_weighted = f1_weighted
        self.false_positive_rate = false_positive_rate
        self.confusion_matrix = confusion_df
        self.per_class_report = per_class_report
        self.matched_rows = matched_rows
        self.unmatched_rows = unmatched_rows


def _merge_predictions_with_truth(
    predictions: pd.DataFrame, ground_truth: pd.DataFrame
) -> pd.DataFrame:
    """Join predictions to ground truth on the natural composite key."""
    key = ["app_id", "library", "version"]
    merged = ground_truth.merge(
        predictions[key + ["risk_level"]],
        on=key,
        how="inner",
        validate="one_to_one",
    )
    return merged


def evaluate(
    predictions: pd.DataFrame, ground_truth: pd.DataFrame
) -> EvaluationReport:
    """
    Compare predicted risk_level to ground_truth_risk_level and compute
    accuracy, precision, recall, F1, false positive rate, and a
    confusion matrix.
    """
    required_pred_cols = {"app_id", "library", "version", "risk_level"}
    if not required_pred_cols.issubset(predictions.columns):
        raise ValueError(
            f"predictions DataFrame missing columns: "
            f"{required_pred_cols - set(predictions.columns)}"
        )

    merged = _merge_predictions_with_truth(predictions, ground_truth)
    matched_rows = len(merged)
    unmatched_rows = len(ground_truth) - matched_rows

    if matched_rows == 0:
        raise ValueError(
            "No rows in dependency_labels.csv matched the predictions on "
            "(app_id, library, version); cannot compute evaluation metrics."
        )

    y_true = merged["ground_truth_risk_level"]
    y_pred = merged["risk_level"]

    labels_present = sorted(
        set(y_true.unique()) | set(y_pred.unique()),
        key=lambda lvl: _RISK_LEVELS_ORDER.index(lvl) if lvl in _RISK_LEVELS_ORDER else 99,
    )

    accuracy = float((y_true.values == y_pred.values).mean())

    precision_w, recall_w, f1_w, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=labels_present, average="weighted", zero_division=0
    )

    precision_c, recall_c, f1_c, support_c = precision_recall_fscore_support(
        y_true, y_pred, labels=labels_present, average=None, zero_division=0
    )
    per_class_report = pd.DataFrame(
        {
            "risk_level": labels_present,
            "precision": precision_c,
            "recall": recall_c,
            "f1_score": f1_c,
            "support": support_c,
        }
    )

    cm = confusion_matrix(y_true, y_pred, labels=labels_present)
    confusion_df = pd.DataFrame(
        cm,
        index=[f"true_{lvl}" for lvl in labels_present],
        columns=[f"pred_{lvl}" for lvl in labels_present],
    )

    # Binary framing for false-positive rate: RISKY = HIGH/CRITICAL.
    y_true_binary = y_true.isin(_RISKY_LEVELS)
    y_pred_binary = y_pred.isin(_RISKY_LEVELS)

    false_positives = int(((~y_true_binary) & (y_pred_binary)).sum())
    true_negatives = int(((~y_true_binary) & (~y_pred_binary)).sum())
    denom = false_positives + true_negatives
    false_positive_rate = float(false_positives / denom) if denom > 0 else 0.0

    if unmatched_rows > 0:
        logger.warning(
            "%d row(s) in dependency_labels.csv had no matching prediction "
            "and were excluded from evaluation.",
            unmatched_rows,
        )

    return EvaluationReport(
        accuracy=round(accuracy, 4),
        precision_weighted=round(float(precision_w), 4),
        recall_weighted=round(float(recall_w), 4),
        f1_weighted=round(float(f1_w), 4),
        false_positive_rate=round(false_positive_rate, 4),
        confusion_df=confusion_df,
        per_class_report=per_class_report,
        matched_rows=matched_rows,
        unmatched_rows=unmatched_rows,
    )


def format_report(report: EvaluationReport) -> str:
    """Render an EvaluationReport as a neatly formatted text block."""
    lines = [
        "=" * 60,
        "SELF-EVALUATION REPORT",
        "=" * 60,
        f"Matched rows   : {report.matched_rows}",
        f"Unmatched rows : {report.unmatched_rows}",
        "-" * 60,
        f"Accuracy            : {report.accuracy:.4f}",
        f"Precision (weighted) : {report.precision_weighted:.4f}",
        f"Recall (weighted)    : {report.recall_weighted:.4f}",
        f"F1 Score (weighted)  : {report.f1_weighted:.4f}",
        f"False Positive Rate  : {report.false_positive_rate:.4f}  "
        f"(RISKY = HIGH/CRITICAL)",
        "-" * 60,
        "Per-class metrics:",
        report.per_class_report.to_string(index=False),
        "-" * 60,
        "Confusion matrix:",
        report.confusion_matrix.to_string(),
        "=" * 60,
    ]
    return "\n".join(lines)
