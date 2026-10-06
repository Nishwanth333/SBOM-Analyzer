import logging

import joblib

logger = logging.getLogger(__name__)
model = joblib.load("logistic_regression_model.joblib")


def prepare_features(data):
    """Align analyzed SBOM data to the trained model's original inputs.

    The analyzer's maintenance stage may replace ``last_updated`` with a
    GitHub release date. Its schema remains unchanged, so the trained model
    receives that updated date and the derived maintenance/risk fields using
    the exact feature names and order captured during training.
    """
    feature_names = getattr(model, "feature_names_in_", None)
    if feature_names is not None:
        expected = list(feature_names)
        missing = [column for column in expected if column not in data.columns]
        if missing:
            raise ValueError(
                "Analyzed SBOM data is missing Logistic Regression feature(s): "
                + ", ".join(missing)
            )
        features = data.loc[:, expected].copy()
    else:
        expected_count = getattr(model, "n_features_in_", None)
        if expected_count is not None and data.shape[1] != expected_count:
            raise ValueError(
                f"Logistic Regression expects {expected_count} features, "
                f"but received {data.shape[1]}."
            )
        features = data.copy()

    logger.info(
        "Prepared %d Logistic Regression feature(s) for %d dependency row(s); "
        "maintenance inputs include last_updated, maintenance_status, "
        "and maintenance_penalty.",
        features.shape[1],
        len(features),
    )
    return features


def predict_risk(data):
    """Return model predictions without changing their trained meanings."""
    features = prepare_features(data)
    return model.predict(features)
