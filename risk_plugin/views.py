import json
import logging
import os
import pickle
from datetime import datetime
from pathlib import Path

from django.contrib.auth.decorators import login_required
from django.db.models import Max, OuterRef, Subquery
from django.http import JsonResponse
from django.utils.timezone import now
from django.views.decorators.http import require_GET

from dojo.models import Finding

from .models import Risk

logger = logging.getLogger(__name__)

WORKDIR = Path(os.getenv("CRIVO_STORAGE_PATH"))
ASSESSMENTS_WORKDIR = WORKDIR / "model/user_assessments"
FEATURES_WORKDIR = WORKDIR / "model/finding_features"

if not ASSESSMENTS_WORKDIR.exists():
    ASSESSMENTS_WORKDIR.mkdir(parents=True)

if not FEATURES_WORKDIR.exists():
    FEATURES_WORKDIR.mkdir(parents=True)


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
        return JsonResponse({"message": "No assessments found. Not updating model."})
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
        return JsonResponse({"message": "No findings available. Not updating model."})

    finding_ids = {finding["id"] for finding in findings_data}
    has_matching_assessment = any(
        assessment["id"] in finding_ids for assessment in assessments_data
    )
    if not has_matching_assessment:
        return JsonResponse({"message": "No matching findings found in assessments. Not updating model."})

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    features_file_path = FEATURES_WORKDIR / f"{request.user.id}_{timestamp}_features.pkl"
    with Path.open(features_file_path, "wb") as f:
        pickle.dump(findings_data, f)
    assessments_file_path = ASSESSMENTS_WORKDIR / f"{request.user.id}_{timestamp}_assessments.pkl"
    with Path.open(assessments_file_path, "wb") as f:
        pickle.dump(assessments_data, f)

    return JsonResponse({"message": "Retraining Model"})
