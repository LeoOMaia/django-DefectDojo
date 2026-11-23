from django import template

register = template.Library()


# This function is used to display the user assessment.
# It returns a tuple with the rating value and a boolean indicating whether it is from the model or not (when not exist the user assessment).
# This helps the HTML template display the assessment in a different way.
@register.simple_tag
def get_assessment(user_assessments, model_inferences, key):
    key = str(key)
    if isinstance(user_assessments, dict) and key in user_assessments:
        user_risk = user_assessments[key]
        if user_risk:
            return user_risk, False
    if isinstance(model_inferences, dict) and key in model_inferences:
        model_risk = model_inferences[key]
        if model_risk:
            return model_risk, True
    return None, False
