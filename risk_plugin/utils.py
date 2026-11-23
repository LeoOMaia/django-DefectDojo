from django.db.models import Max, OuterRef, Subquery

from .models import Risk


def _latest_risks_by_finding(user_id, *, is_model_inference):
    if user_id is None:
        return {}

    latest_timestamp_subquery = Risk.objects.filter(
        user_id=user_id,
        finding_id=OuterRef("finding_id"),
        is_model_inference=is_model_inference,
    ).values("finding_id").annotate(
        latest_timestamp=Max("timestamp"),
    ).values("latest_timestamp")

    rows = Risk.objects.filter(
        user_id=user_id,
        is_model_inference=is_model_inference,
        timestamp=Subquery(latest_timestamp_subquery),
    ).order_by("id").values("finding_id", "risk_class", "timestamp")

    return {
        str(row["finding_id"]): (row["risk_class"], row["timestamp"])
        for row in rows
        if row["risk_class"]
    }


def get_user_assessments(user_id):
    user_latest = _latest_risks_by_finding(user_id, is_model_inference=False)
    model_latest = _latest_risks_by_finding(user_id, is_model_inference=True)

    result = {}
    for fid_str, (risk_class, user_ts) in user_latest.items():
        # If the user cleared a rating to "NA", allow a newer model inference to take precedence.
        if risk_class == "NA" and fid_str in model_latest:
            _, model_ts = model_latest[fid_str]
            if model_ts and user_ts and model_ts > user_ts:
                continue
        result[fid_str] = risk_class
    return result


def get_model_inferences(user_id):
    model_latest = _latest_risks_by_finding(user_id, is_model_inference=True)
    return {fid_str: risk_class for fid_str, (risk_class, _) in model_latest.items()}
