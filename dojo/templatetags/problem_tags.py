from dojo.models import Finding

from django import template

register = template.Library()

@register.filter
def count_distinct_script_ids(findings):
    return len(set(finding.vuln_id_from_tool for finding in findings))