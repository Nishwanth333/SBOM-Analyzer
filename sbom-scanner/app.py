"""Flask entry point for SBOM analysis, reporting, and updated SBOM downloads.

Uploads run the rule-based risk engine and ML prediction pipeline. For mapped
GitHub projects, the analyzer also creates a separate SBOM copy with newer
parseable release versions while keeping the originally uploaded versions for
risk analysis.
"""

import logging
import uuid
from pathlib import Path
from src.main import analyze_all
from ml_risk import predict_risk


from flask import (
    Flask, Response, abort, flash, redirect, render_template,
    request, send_file, url_for,
)
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
import pandas as pd

import report as report_module

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
RESULTS_DIR = UPLOAD_DIR / "results"

# Maps each upload form field to the file extension it must have.
EXPECTED_EXTENSIONS = {
    "applications_file": ".json",
    "dependencies_file": ".csv",
}

UPLOAD_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SECRET_KEY"] = "dev-secret-change-me"  # TODO: override via environment in production
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload limit

logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _has_expected_extension(file: FileStorage, expected_extension: str) -> bool:
    """Check a FileStorage's filename against a required extension (case-insensitive)."""
    return bool(file and file.filename) and file.filename.lower().endswith(expected_extension)


def _load_results(report_id: str) -> pd.DataFrame:
    """Load a previously generated analysis result set, or 404 if it doesn't exist."""
    results_path = RESULTS_DIR / f"{report_id}.csv"
    if not results_path.exists():
        abort(404, description="Report not found. Please upload SBOM files again.")
    return pd.read_csv(results_path)


def _write_updated_sbom(
    dependencies_path: Path, results_df: pd.DataFrame, output_path: Path
) -> int:
    """Write a separate SBOM copy with verified newer release versions.

    The uploaded dependency file remains unchanged and is still the source for
    vulnerability/risk analysis. Only versions confirmed newer by the
    GitHub release metadata are changed in this downloadable copy.
    """
    dependencies = pd.read_csv(dependencies_path)
    app_column = "app_id" if "app_id" in dependencies.columns else "application_id"

    def clean(value) -> str:
        return "" if pd.isna(value) else str(value).strip()

    latest_by_dependency = {}
    for row in results_df.itertuples(index=False):
        if not bool(getattr(row, "update_available", False)):
            continue
        latest = clean(getattr(row, "latest_version", None))
        if not latest:
            continue
        key = (
            clean(getattr(row, "app_id", None)),
            clean(getattr(row, "library", None)),
            clean(getattr(row, "version", None)),
        )
        latest_by_dependency[key] = latest

    updated_count = 0
    for index, row in dependencies.iterrows():
        key = (
            clean(row.get(app_column)),
            clean(row.get("library")),
            clean(row.get("version")),
        )
        latest = latest_by_dependency.get(key)
        if latest:
            dependencies.at[index, "version"] = latest
            updated_count += 1

    dependencies.to_csv(output_path, index=False)
    return updated_count


# ---------------------------------------------------------------------------
# Upload routes
# ---------------------------------------------------------------------------
@app.route("/")
def index() -> str:
    """Upload page."""
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload() -> Response:
    
    apps_file = request.files.get("applications_file")
    deps_file = request.files.get("dependencies_file")

    if not apps_file or not deps_file or not apps_file.filename or not deps_file.filename:
        flash("Please upload both an applications file (JSON) and a dependencies file (CSV).", "danger")
        return redirect(url_for("index"))

    if not _has_expected_extension(apps_file, EXPECTED_EXTENSIONS["applications_file"]):
        flash(f"'{apps_file.filename}' is invalid — the applications file must be a .json file.", "danger")
        return redirect(url_for("index"))

    if not _has_expected_extension(deps_file, EXPECTED_EXTENSIONS["dependencies_file"]):
        flash(f"'{deps_file.filename}' is invalid — the dependencies file must be a .csv file.", "danger")
        return redirect(url_for("index"))

    apps_filename = secure_filename(apps_file.filename)
    deps_filename = secure_filename(deps_file.filename)

    upload_id = uuid.uuid4().hex[:10]
    upload_session_dir = UPLOAD_DIR / upload_id
    upload_session_dir.mkdir(parents=True, exist_ok=True)

    try:
        apps_file.save(upload_session_dir / apps_filename)
        deps_file.save(upload_session_dir / deps_filename)
    except OSError as exc:
        app.logger.error("Failed to save uploaded files for %s: %s", upload_id, exc)
        flash("Failed to save uploaded files. Please try again.", "danger")
        return redirect(url_for("index"))

    results_df = analyze_all(
        upload_session_dir / apps_filename,
        upload_session_dir / deps_filename,
        BASE_DIR / "data" / "sample_inputs" / "vulnerability_db.json",
        BASE_DIR / "data" / "sample_inputs" / "license_rules.json",
    )

    print("ANALYSIS COMPLETED")

    ml_input = results_df.drop(columns=["flags"], errors="ignore")

    results_df["ml_prediction"] = predict_risk(ml_input)

    print("ML PREDICTION COMPLETED")
    print(results_df["ml_prediction"].value_counts())

    results_df.to_csv(RESULTS_DIR / f"{upload_id}.csv", index=False)
    updated_count = _write_updated_sbom(
        upload_session_dir / deps_filename,
        results_df,
        RESULTS_DIR / f"{upload_id}_updated_sbom.csv",
    )
    app.logger.info(
        "Created updated SBOM for upload %s; advanced %d dependency version(s).",
        upload_id,
        updated_count,
    )

    return redirect(url_for("dashboard", report_id=upload_id))

    flash("Files uploaded successfully!", "success")
    return render_template(
        "index.html",
        uploaded_files={
            "applications": apps_filename,
            "dependencies": deps_filename,
            "upload_id": upload_id,
        },
    )


# ---------------------------------------------------------------------------
# Analysis & report routes
# ---------------------------------------------------------------------------
@app.route("/dashboard/<report_id>")
def dashboard(report_id: str) -> str:
    """Main risk dashboard: per-app summary + top risky libraries."""
    df = _load_results(report_id)
    # Result files from the scanner use `application_name`; the dashboard's
    # mock/report pipeline may instead provide `app_name`. Normalize both so
    # the application column never renders empty because of a schema variant.
    if "app_name" not in df.columns:
        if "application_name" in df.columns:
            df["app_name"] = df["application_name"]
        else:
            df["app_name"] = df["app_id"].map(lambda value: f"App {value}")
    df["app_name"] = df["app_name"].fillna("").astype(str).str.strip()
    blank_names = df["app_name"].eq("")
    if "app_id" in df.columns:
        df.loc[blank_names, "app_name"] = df.loc[blank_names, "app_id"].map(lambda value: f"App {value}")
    df.loc[df["app_name"].eq(""), "app_name"] = "Unknown application"

    per_app = (
        df.groupby(["app_id", "app_name"])
        .agg(
            avg_risk_score=("risk_score", "mean"),
            max_risk_score=("risk_score", "max"),
            total_libraries=("library", "count"),
            flagged_libraries=("risk_type", lambda s: (s.str.upper() != "NONE").sum()),
        )
        .reset_index()
        .sort_values("avg_risk_score", ascending=False)
    )

    summary = {
        "total_apps": int(df["app_id"].nunique()),
        "total_libraries": int(len(df)),
        "total_flagged": int((df["risk_type"].str.upper() != "NONE").sum()),
        "critical_count": int((df["severity"].str.upper() == "CRITICAL").sum()),
        "high_count": int((df["severity"].str.upper() == "HIGH").sum()),
    }

    top_risky = df.sort_values("risk_score", ascending=False).head(15)
    update_count = (
        int(df["update_available"].fillna(False).astype(bool).sum())
        if "update_available" in df.columns
        else 0
    )

    return render_template(
        "dashboard.html",
        report_id=report_id,
        per_app=per_app.to_dict(orient="records"),
        summary=summary,
        top_risky=top_risky.to_dict(orient="records"),
        chart_labels=per_app["app_name"].tolist(),
        chart_scores=[round(score, 1) for score in per_app["avg_risk_score"].tolist()],
        update_count=update_count,
    )


@app.route("/report/<report_id>/updated-sbom")
def updated_sbom(report_id: str) -> Response:
    """Download an SBOM copy with newer mapped GitHub release versions."""
    path = RESULTS_DIR / f"{report_id}_updated_sbom.csv"
    if not path.is_file():
        abort(404, description="Updated SBOM not found. Please upload SBOM files again.")
    return send_file(
        path,
        as_attachment=True,
        download_name=f"sbom_updated_{report_id}.csv",
        mimetype="text/csv",
    )


@app.route("/report/<report_id>/html")
def report_html(report_id: str) -> str:
    """Printable / shareable HTML compliance report."""
    df = _load_results(report_id)
    context = report_module.build_report_context(df, report_id)
    return render_template("report_template.html", **context)


@app.route("/report/<report_id>/pdf")
def report_pdf(report_id: str) -> Response:
    """Download the compliance report as a PDF."""
    df = _load_results(report_id)
    pdf_path = RESULTS_DIR / f"{report_id}_report.pdf"
    report_module.generate_pdf_report(df, report_id, pdf_path)
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"sbom_risk_report_{report_id}.pdf",
        mimetype="application/pdf",
    )


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(error) -> tuple:
    """Friendly 404 page — most commonly hit when a report_id no longer exists."""
    return render_template("index.html", error=str(error.description)), 404


@app.errorhandler(RequestEntityTooLarge)
def file_too_large(_error) -> Response:
    """Friendly message instead of a raw 413 when an upload exceeds MAX_CONTENT_LENGTH."""
    flash("One of your files is too large. The upload limit is 10 MB per file.", "danger")
    return redirect(url_for("index"))


@app.errorhandler(500)
def server_error(error) -> tuple:
    """Friendly 500 page; logs the underlying error for debugging."""
    app.logger.error("Unhandled server error: %s", error)
    flash("Something went wrong on our end. Please try again.", "danger")
    return redirect(url_for("index")), 500


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
