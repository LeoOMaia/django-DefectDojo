import json
import os
import requests

from django.conf import settings

from dojo.models import Finding

import logging
logger = logging.getLogger(__name__)

MEDIA_ROOT = os.getenv('DD_MEDIA_ROOT', '/app/media')
CACHED_JSON_DISAMBIGUATOR = os.path.join(MEDIA_ROOT, 'cached_disambiguator.json')

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
    response = requests.get(json_url, timeout=5, verify=False)
    response.raise_for_status()
    return response.json()

def load_cached_json():
    if os.path.exists(CACHED_JSON_DISAMBIGUATOR):
        try:
            with open(CACHED_JSON_DISAMBIGUATOR, 'r') as f:
                data = json.load(f)
                if validate_json(data):
                    return data
                else:
                    logger.warning('Cached JSON failed validation.')
        except json.JSONDecodeError:
            logger.error('Error decoding JSON from cache.')
        except Exception as e:
            logger.error(f'Unexpected error loading JSON from cache: {e}')
    else:
        logger.info('Cached JSON file does not exist.')
    return None

def mapping_script_problem_id(mappings_json_findings):
    script_to_problem_mapping = {
        script_id: key
        for key, script_ids in mappings_json_findings.items()
        for script_id in script_ids
    }
    return script_to_problem_mapping

def save_json_to_cache(data):
    logger.info('Saving disambiguator JSON to cache and updating problem cache.')
    with open(CACHED_JSON_DISAMBIGUATOR, 'w') as f:
        json.dump(data, f)

def load_json(check_cache=True):
    try:
        if check_cache:
            cached_data = load_cached_json()
            if cached_data and validate_json(cached_data):
                return mapping_script_problem_id(cached_data)

        if settings.PROBLEM_MAPPINGS_JSON_URL:
            data = download_json(settings.PROBLEM_MAPPINGS_JSON_URL)
            if validate_json(data):
                save_json_to_cache(data)
                return mapping_script_problem_id(data)
        else:
            logger.error('No disambiguator JSON URL provided.')
    except requests.RequestException as e:
        logger.error('HTTP error while loading JSON: %s', e)
    except json.JSONDecodeError as e:
        logger.error('JSON decoding error: %s', e)
    except Exception as e:
        logger.error('Unexpected error: %s', e)
    return {}
