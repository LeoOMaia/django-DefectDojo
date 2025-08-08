from django.db.models import Max, OuterRef, Subquery

from .models import Risk


def get_user_assessments(user_id):
    latest_timestamp_subquery = Risk.objects.filter(
        user_id=user_id,
        finding_id=OuterRef("finding_id"),
        is_model_inference=False,
    ).values("finding_id").annotate(
        latest_timestamp=Max("timestamp"),
    ).values("latest_timestamp")

    latest_assessments = Risk.objects.filter(
        user_id=user_id,
        is_model_inference=False,
        timestamp=Subquery(latest_timestamp_subquery),
    ).values("finding_id", "risk_class")

    return {str(v["finding_id"]): v["risk_class"] for v in latest_assessments}


def get_model_inferences(user_id):
    latest_timestamp_subquery = Risk.objects.filter(
        user_id=user_id,
        finding_id=OuterRef("finding_id"),
        is_model_inference=True,
    ).values("finding_id").annotate(
        latest_timestamp=Max("timestamp"),
    ).values("latest_timestamp")

    latest_inferences = Risk.objects.filter(
        user_id=user_id,
        is_model_inference=True,
        timestamp=Subquery(latest_timestamp_subquery),
    ).values("finding_id", "risk_class")

    return {str(v["finding_id"]): v["risk_class"] for v in latest_inferences}
