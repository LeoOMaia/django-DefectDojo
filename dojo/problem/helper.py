import json
import logging
from pathlib import Path
from urllib.parse import urlparse

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

parsed_url = urlparse(settings.PROBLEM_MAPPINGS_JSON_URL)
if parsed_url.scheme == "file":
    CACHED_JSON_DISAMBIGUATOR = Path(f"/app/crivo-metadata/{Path(parsed_url.path).name}")
else:
    CACHED_JSON_DISAMBIGUATOR = Path("/app/crivo-metadata/cached_disambiguator.json")


def validate_json(data):
    if not isinstance(data, dict):
        return False
    for key, value in data.items():
        if not isinstance(key, str) or not isinstance(value, list):
            return False
        if not all(isinstance(item, str) for item in value):
            return False
    return True


def download_json(json_url):
    parsed_url = urlparse(json_url)
    if parsed_url.scheme in ["http", "https"]:
        logger.info("Downloading disambiguator JSON from %s", json_url)
        response = requests.get(json_url, timeout=5, verify=True)
        response.raise_for_status()
        return True, response.json()

    if parsed_url.scheme == "file":
        logger.info("Loading disambiguator JSON from file %s", parsed_url.path)
        file_path = parsed_url.path
        with open(file_path, encoding="utf-8") as file:
            return False, json.load(file)

    return False, None


def load_cached_json():
    if CACHED_JSON_DISAMBIGUATOR.exists():
        try:
            with CACHED_JSON_DISAMBIGUATOR.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if validate_json(data):
                    return data
                logger.warning("Cached JSON failed validation.")
        except json.JSONDecodeError:
            logger.error("Error decoding JSON from cache.")
        except Exception as e:
            logger.error(f"Unexpected error loading JSON from cache: {e}")
    else:
        logger.info("Cached JSON file does not exist.")

    return None


def mapping_script_problem_id(mappings_json_findings):
    return {
        script_id: key
        for key, script_ids in mappings_json_findings.items()
        for script_id in script_ids
    }


def save_json_to_cache(data):
    logger.info("Saving disambiguator JSON to cache and updating problem cache.")
    with open(CACHED_JSON_DISAMBIGUATOR, "w", encoding="utf-8") as f:
        json.dump(data, f)


def load_json(check_cache=True):
    try:
        if check_cache:
            cached_data = load_cached_json()
            if cached_data and validate_json(cached_data):
                return mapping_script_problem_id(cached_data)

        if settings.PROBLEM_MAPPINGS_JSON_URL:
            save_json, data = download_json(settings.PROBLEM_MAPPINGS_JSON_URL)
            if validate_json(data):
                if save_json:
                    save_json_to_cache(data)
                return mapping_script_problem_id(data)

        logger.error("No disambiguator JSON URL provided.")
    except requests.RequestException as e:
        logger.error("Error while loading JSON: %s", e)
    except json.JSONDecodeError as e:
        logger.error("JSON decoding error: %s", e)
    except Exception as e:
        logger.error("Unexpected error: %s", e)

    return {}
