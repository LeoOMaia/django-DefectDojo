from django import template

register = template.Library()


# This function is used to display the user assessment.
# It returns a tuple with the rating value and a boolean indicating whether it is from the model or not (when not exist the user assessment).
# This helps the HTML template display the assessment in a different way.
@register.simple_tag
def get_assessment(user_assessments, model_inferences, key):
    key = str(key)
    if key in user_assessments:
        return user_assessments[key], False
    if key in model_inferences:
        return model_inferences[key], True
    return None, False
