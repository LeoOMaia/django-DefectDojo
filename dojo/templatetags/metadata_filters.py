from django import template

register = template.Library()


@register.filter
def cve_url(cve_id: str) -> str:
    """
    Converts a CVE ID into a URL to the NVD page for that CVE.
    Example: CVE-2023-12345 -> https://nvd.nist.gov/vuln/detail/CVE-2023-1234
    """
    base_url = "https://nvd.nist.gov/vuln/detail/"
    return f"{base_url}{cve_id}" if cve_id else ""


@register.filter
def cwe_url(cwe_id: str) -> str:
    """
    Converts a CWE ID into a URL to the CWE page for that CWE.
    Example: CWE-123 -> https://cwe.mitre.org/data/definitions/123.html
    """
    if not cwe_id or "-" not in cwe_id:
        return ""
    cwe_num = cwe_id.split("-", 1)[1]
    if not cwe_num.isdigit():
        return ""
    base_url = "https://cwe.mitre.org/data/definitions/"
    return f"{base_url}{cwe_num}.html"


@register.filter
def split(string: str, delimiter: str) -> list[str]:
    """
    Split a string by the delimiter and return the resulting list.
    Example: 'cpe:2.3:a:synacor:zimbra_collaboration_suite:8.8.15:-:*:*:*:*:*:*' -> ["cpe", "2.3", "a", "synacor", "zimbra_collaboration_suite", "8.8.15", "-", "*", "*", "*", "*", "*", "*"]
    """
    return string.split(delimiter)


@register.filter
def remove_cpe_duplicates(data: list[str]) -> tuple[tuple[str, str], ...]:
    pairs = []
    for string in data or []:
        parts = string.split(":")
        if len(parts) >= 5:
            pairs.append((parts[3], parts[4]))
    return tuple(set(pairs))
