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
    script_ids: set = field(default_factory=set)
    finding_ids: set = field(default_factory=set)

    def to_dict(self):
        return {
            "name": self.name,
            "problem_id": self.problem_id,
            "severity": self.severity,
            "script_ids": list(self.script_ids),
            "finding_ids": list(self.finding_ids),
        }

    @staticmethod
    def from_dict(data):
        return Problem(
            name=data["name"],
            problem_id=data["problem_id"],
            severity=data["severity"],
            script_ids=set(data.get("script_ids", [])),
            finding_ids=set(data.get("finding_ids", [])),
        )

    @classmethod
    def load_from_id(cls, problem_id, redis_client):
        problem_data = redis_client.hget("problems", problem_id)
        if problem_data:
            return cls.from_dict(json.loads(problem_data))
        return None

    def add_finding(self, finding):
        if finding.id not in self.finding_ids:
            if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[self.severity]:
                self.name = finding.title
                self.severity = finding.severity
            self.finding_ids.add(finding.id)
            self.script_ids.add(finding.vuln_id_from_tool)

    def remove_finding(self, finding_id):
        self.finding_ids.remove(finding_id)
        findings = Finding.objects.filter(id__in=self.finding_ids)
        severity, name, script_ids = "Info", "", set()
        for finding in findings:
            script_ids.add(finding.vuln_id_from_tool)
            if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[severity]:
                name = finding.title
                severity = finding.severity
        self.name = name
        self.severity = severity
        self.script_ids = script_ids

    def persist(self, redis_client):
        if not self.finding_ids:
            redis_client.hdel("problems", self.problem_id)
        else:
            redis_client.hset("problems", self.problem_id, json.dumps(self.to_dict()))


class ProblemHelper:
    @staticmethod
    def add_finding(finding):
        ProblemHelper.remove_finding(int(finding.id))
        if finding.vuln_id_from_tool and finding.severity != "Info":
            redis_client = get_redis_client()
            if redis_client.exists("problems") and redis_client.exists("id_to_problem"):
                problem_id = problem_id_b64encode(finding.vuln_id_from_tool)
                problem = Problem.load_from_id(problem_id, redis_client)
                if not problem:
                    problem = Problem(problem_id)
                problem.add_finding(finding)
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
                    problem.remove_finding(finding_id)
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
    if redis_client.exists("problems", "id_to_problem"):
        problems_data = redis_client.hgetall("problems")
        problems = {key: Problem.from_dict(json.loads(value)) for key, value in problems_data.items()}
        id_to_problem_data = redis_client.hgetall("id_to_problem")
        id_to_problem = {int(key): value for key, value in id_to_problem_data.items()}
        return problems, id_to_problem

    problems = {}
    id_to_problem = {}
    for finding in Finding.objects.all():
        if finding.vuln_id_from_tool and finding.severity != "Info":
            find_or_create_problem(finding, problems, id_to_problem)

    redis_client.delete("problems")
    redis_client.delete("id_to_problem")
    problems_data = {key: json.dumps(value.to_dict()) for key, value in problems.items()}
    id_to_problem_data = dict(id_to_problem)
    for key, value in problems_data.items():
        redis_client.hset("problems", key, value)
    for key, value in id_to_problem_data.items():
        redis_client.hset("id_to_problem", key, value)

    return problems, id_to_problem


def find_or_create_problem(finding, problems, id_to_problem):
    problem_id = problem_id_b64encode(finding.vuln_id_from_tool)
    if problem_id not in problems:
        problems[problem_id] = Problem(problem_id)
    problems[problem_id].add_finding(finding)
    id_to_problem[finding.id] = problem_id
