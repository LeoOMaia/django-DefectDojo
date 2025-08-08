import os

CRIVO_METADATA_DIR = os.getenv("CRIVO_STORAGE_PATH", "/app/crivo-metadata")

# Risk Plugin
INSTALLED_APPS += ("risk_plugin",)

DATABASES["risk"] = {
    "ENGINE": "django.db.backends.sqlite3",
    "NAME": f"{CRIVO_METADATA_DIR}/findings_risk.db",
}

DATABASE_ROUTERS = ["risk_plugin.router.RiskRouter"]

try:
    MIGRATION_MODULES.update({"risk_plugin": "risk_plugin.migrations"})
except NameError:
    print("Error: MIGRATION_MODULES is not defined. Make sure it is defined before updating it.")

# CVE Metadata
CVE_CLASSIFICATION_THRESHOLD = 0.4
CVE_METADATA_DIR = f"{CRIVO_METADATA_DIR}/cve-metadata"
CVE_METADATA_PICKLE = f"{CRIVO_METADATA_DIR}/cve-metadata.pkl"
