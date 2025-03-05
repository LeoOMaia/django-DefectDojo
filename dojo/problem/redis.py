import base64
import json
import logging
from dataclasses import dataclass, field
from functools import lru_cache

import redis

import dojo.problem.helper as problems_help
from dojo.models import Finding

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1,
}


@dataclass
class Problem:
    problem_id: str
    name: str = ""
    severity: str = "Info"
    main_finding_id: int = None
    finding_ids: set = field(default_factory=set)
    script_ids: set = field(default_factory=set)

    def to_dict(self):
        return {
            "name": self.name,
            "problem_id": self.problem_id,
            "severity": self.severity,
            "main_finding_id": self.main_finding_id,
            "finding_ids": list(self.finding_ids),
            "script_ids": list(self.script_ids),
        }

    @staticmethod
    def from_dict(data):
        return Problem(
            name=data["name"],
            problem_id=data["problem_id"],
            severity=data["severity"],
            main_finding_id=data.get("main_finding_id"),
            finding_ids=set(data.get("finding_ids", [])),
            script_ids=set(data.get("script_ids", [])),
        )

    @staticmethod
    def load_from_id(problem_id, redis_client):
        problem_data = redis_client.hget("problems", problem_id)
        if problem_data:
            return Problem.from_dict(json.loads(problem_data))
        return None

    def persist(self, redis_client):
        if not self.finding_ids:
            redis_client.hdel("problems", self.problem_id)
        else:
            redis_client.hset("problems", self.problem_id, json.dumps(self.to_dict()))

    def update_name_sev(self, finding):
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[self.severity]:
            self.name = finding.title
            self.severity = finding.severity
            self.main_finding_id = finding.id

    @staticmethod
    def add_finding(finding):
        Problem.remove_finding(int(finding.id))
        if finding.vuln_id_from_tool and finding.severity != "Info":
            redis_client = get_redis_client()
            problem_id = problem_id_b64encode(finding.vuln_id_from_tool)
            problem = Problem.load_from_id(problem_id, redis_client)
            if not problem:
                problem = Problem(problem_id)
            if finding.id not in problem.finding_ids:
                problem.update_name_sev(finding)
                problem.finding_ids.add(finding.id)
                problem.script_ids.add(finding.vuln_id_from_tool)
            problem.persist(redis_client)
            redis_client.hset("id_to_problem", finding.id, problem_id)

    @staticmethod
    def remove_finding(finding_id):
        redis_client = get_redis_client()
        if redis_client.exists("problems") and redis_client.exists("id_to_problem"):
            problem_id = redis_client.hget("id_to_problem", finding_id)
            if problem_id:
                problem = Problem.load_from_id(problem_id, redis_client)
                if problem:
                    # This is why we do not use Redis set functionality to store Findings associated with a Problem.
                    # We need to iterate over Findings anyway whenever a Finding is deleted or changed to update the Problem definition.
                    problem.finding_ids.remove(finding_id)
                    if finding_id == problem.main_finding_id:
                        problem.severity = "Info"
                        findings = Finding.objects.filter(id__in=problem.finding_ids)
                        for finding in findings:
                            problem.update_name_sev(finding)

                    # renew quantity of script_ids if necessary
                    remaining_script_ids = {finding.vuln_id_from_tool for finding in Finding.objects.filter(id__in=problem.finding_ids)}
                    problem.script_ids.intersection_update(remaining_script_ids)

                    problem.persist(redis_client)
                redis_client.hdel("id_to_problem", finding_id)


@lru_cache(maxsize=1)
def get_redis_client():
    return redis.Redis(host="django-defectdojo-redis-1", port=6379, decode_responses=True)


def problem_id_b64encode(script_id):
    script_to_problem_mapping = problems_help.load_json()
    problem_id = script_to_problem_mapping.get(script_id, script_id)
    return base64.b64encode(problem_id.encode()).decode()


def dict_problems_findings():
    redis_client = get_redis_client()
    if redis_client.exists("problems") and redis_client.exists("id_to_problem"):
        return _load_problems_from_redis(redis_client)

    # Rebuild problems
    redis_client.delete("problems", "id_to_problem")
    for finding in Finding.objects.all():
        Problem.add_finding(finding)
    return _load_problems_from_redis(redis_client)


def _load_problems_from_redis(redis_client):
    problems_data = redis_client.hgetall("problems")
    id_to_problem_data = redis_client.hgetall("id_to_problem")
    if problems_data:
        problems = {key: Problem.from_dict(json.loads(value)) for key, value in problems_data.items()}
        id_to_problem = {int(key): value for key, value in id_to_problem_data.items()}
        return problems, id_to_problem
    return {}, {}
