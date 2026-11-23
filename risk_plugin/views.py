import json
import logging
import os
import pickle
import re
from datetime import datetime
from pathlib import Path

from django.contrib.auth.decorators import login_required
from django.db.models import Max, OuterRef, Subquery
from django.http import JsonResponse
from django.utils.dateparse import parse_datetime
from django.utils.timezone import now
from django.views.decorators.http import require_GET

from dojo.models import Finding

from .models import Risk

logger = logging.getLogger(__name__)

WORKDIR = Path(os.getenv("CRIVO_STORAGE_PATH", "/app/crivo-metadata"))
ASSESSMENTS_WORKDIR = WORKDIR / "model/user_assessments"
FEATURES_WORKDIR = WORKDIR / "model/finding_features"
STATUS_WORKDIR = WORKDIR / "model/status"
JOB_ID_PATTERN = re.compile(r"^\d+_\d{8}_\d{6}$")


def _ensure_workdirs():
    for directory in (ASSESSMENTS_WORKDIR, FEATURES_WORKDIR):
        directory.mkdir(parents=True, exist_ok=True)
    try:
        STATUS_WORKDIR.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        logger.warning("Cannot create %s due to permissions; falling back to DB/file polling.", STATUS_WORKDIR)


def _atomic_pickle_dump(data, target_path: Path):
    tmp_path = target_path.with_name(f".{target_path.name}.tmp")
    with Path.open(tmp_path, "wb") as f:
        pickle.dump(data, f)
    tmp_path.replace(target_path)


@login_required
def save_user_assessment(request):
    logger.debug("Received a request.")

    if request.method != "POST":
        logger.error("Invalid request method.")
        return JsonResponse({"error": "Method Not Allowed"}, status=405)

    try:
        data = json.loads(request.body)
        logger.debug(f"Request body data: {data}")

        finding_id = int(data.get("finding_id"))
        risk_value = data.get("risk")
        risk_type = data.get("risk_type")

        if risk_type == "class" and risk_value not in [choice[0] for choice in Risk.RISK_CHOICES_CLASS]:
            logger.error("Invalid risk value for class.")
            return JsonResponse({"error": "Invalid Risk"}, status=400)
        if risk_type == "num" and risk_value not in [choice[0] for choice in Risk.RISK_CHOICES_NUM]:
            logger.error("Invalid risk value for num.")
            return JsonResponse({"error": "Invalid Risk"}, status=400)

        risk_kwargs = {
            "user_id": request.user.id,
            "finding_id": finding_id,
            "timestamp": now(),
        }

        if risk_type == "class":
            risk_kwargs["risk_class"] = risk_value
        elif risk_type == "num":
            risk_kwargs["risk_num"] = risk_value

        Risk.objects.create(**risk_kwargs)

        return JsonResponse({"message": "Risk Saved"})

    except (ValueError, TypeError, json.JSONDecodeError) as e:
        logger.error(f"Error while processing the Risk: {e}")
        return JsonResponse({"error": "Invalid Data"}, status=400)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return JsonResponse({"error": "An unexpected error occurred"}, status=500)


@require_GET
@login_required
def update_inferences(request):
    user_id = request.user.id

    latest_timestamps = Risk.objects.filter(
        user_id=user_id,
        is_model_inference=False,
        finding_id=OuterRef("finding_id"),
    ).values("finding_id").annotate(
        max_timestamp=Max("timestamp"),
    ).values("max_timestamp")

    latest_assessments = Risk.objects.filter(
        user_id=user_id,
        is_model_inference=False,
        timestamp=Subquery(latest_timestamps),
    )

    assessments_data = [
        {
            "id": assessment.finding_id,
            "user_id": assessment.user_id,
            "risk_class": assessment.risk_class,
            "timestamp": assessment.timestamp.isoformat(),
        }
        for assessment in latest_assessments
    ]
    if not assessments_data:
        return JsonResponse({"status": "noop", "message": "No assessments found. Not updating model."})
    findings_data = [
        {
            "id": finding.id,
            "title": finding.title,
            "date": finding.date,
            "description": finding.description,
            "severity": finding.severity,
            "vuln_id_from_tool": finding.vuln_id_from_tool,
            "mitigation": finding.mitigation,
            "epss_score": finding.epss_score,
            "epss_percentile": finding.epss_percentile,
            "cve": finding.cve,
        }
        for finding in Finding.objects.all()
    ]
    if not findings_data:
        return JsonResponse({"status": "noop", "message": "No findings available. Not updating model."})

    finding_ids = {finding["id"] for finding in findings_data}
    rated_finding_ids = {
        assessment["id"]
        for assessment in assessments_data
        if assessment["id"] in finding_ids and assessment["risk_class"] not in {"", "NA", None}
    }
    if not rated_finding_ids:
        return JsonResponse({"status": "noop", "message": "No rated assessments found. Not updating model."})

    if finding_ids.issubset(rated_finding_ids):
        return JsonResponse({"status": "noop", "message": "All findings already have user assessments."})

    _ensure_workdirs()
    started_at = now()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    job_id = f"{user_id}_{timestamp}"
    status_file_path = STATUS_WORKDIR / f"{job_id}.json"
    try:
        if status_file_path.exists():
            status_file_path.unlink(missing_ok=True)
    except OSError:
        logger.debug("Could not clear previous status file %s", status_file_path)

    features_file_path = FEATURES_WORKDIR / f"{job_id}_features.pkl"
    _atomic_pickle_dump(findings_data, features_file_path)
    assessments_file_path = ASSESSMENTS_WORKDIR / f"{job_id}_assessments.pkl"
    _atomic_pickle_dump(assessments_data, assessments_file_path)

    return JsonResponse({
        "status": "processing",
        "message": "Retraining model...",
        "job_id": job_id,
        "started_at": started_at.isoformat(),
    })


@require_GET
@login_required
def inference_status(request):
    user_id = request.user.id
    job_id = request.GET.get("job_id", "")
    started_at_raw = request.GET.get("started_at", "")

    if not JOB_ID_PATTERN.match(job_id) or not job_id.startswith(f"{user_id}_"):
        return JsonResponse({"status": "error", "message": "Invalid job identifier."}, status=400)

    started_at = parse_datetime(started_at_raw) if started_at_raw else None
    status_file_path = STATUS_WORKDIR / f"{job_id}.json"
    if started_at is not None and Risk.objects.filter(
        user_id=user_id,
        is_model_inference=True,
        timestamp__gte=started_at,
    ).exists():
        try:
            status_file_path.unlink(missing_ok=True)
        except OSError:
            pass
        return JsonResponse({"status": "completed", "message": "Inferences updated! Reloading..."})

    try:
        if status_file_path.is_file():
            try:
                payload = json.loads(status_file_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = {"status": "error", "message": "Failed to read model status."}
            if payload.get("status") in {"completed", "error"}:
                try:
                    status_file_path.unlink(missing_ok=True)
                except OSError:
                    pass
                return JsonResponse(payload)
    except OSError:
        pass

    return JsonResponse({"status": "processing", "message": "Retraining model..."})
