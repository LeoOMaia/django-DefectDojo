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
    name: str
    problem_id: str
    severity: str
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


@lru_cache(maxsize=1)
def get_redis_client():
    return redis.Redis(host="django-defectdojo-redis-1", port=6379, decode_responses=True)


def remove_finding_from_redis(finding_id_to_remove):
    redis_client = get_redis_client()
    if redis_client.exists("problems", "id_to_problem"):
        problem_id = redis_client.hget("id_to_problem", finding_id_to_remove)
        if problem_id:
            problem = Problem.from_dict(json.loads(redis_client.hget("problems", problem_id)))
            problem.finding_ids.remove(finding_id_to_remove)
            if not problem.finding_ids:
                redis_client.hdel("problems", problem_id)
            else:
                # We do not use Redis' set functionality to store Findings associated with a Problem
                # because we need to iterate over Findings whenever a Finding is deleted to update the
                # Problem definition.
                findings = Finding.objects.filter(id__in=problem.finding_ids)
                severity, name, script_ids = "Info", "", set()
                for finding in findings:
                    script_ids.add(finding.vuln_id_from_tool)
                    if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[severity]:
                        name = finding.title
                        severity = finding.severity
                problem.name = name
                problem.severity = severity
                problem.script_ids = script_ids
                redis_client.hset("problems", problem_id, json.dumps(problem.to_dict()))
            redis_client.hdel("id_to_problem", finding_id_to_remove)
    else:
        dict_problems_findings()


def add_finding_to_redis(finding):
    def update_problem(redis_client, problem, finding):
        problem.finding_ids.add(finding.id)
        problem.script_ids.add(finding.vuln_id_from_tool)

        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[problem.severity]:
            problem.name = finding.title
            problem.severity = finding.severity

        redis_client.hset("problems", problem_id, json.dumps(problem.to_dict()))
        redis_client.hset("id_to_problem", finding.id, problem_id)

    remove_finding_from_redis(int(finding.id))
    if finding.vuln_id_from_tool and finding.severity != "Info":
        redis_client = get_redis_client()
        if redis_client.exists("problems", "id_to_problem"):
            script_id = finding.vuln_id_from_tool
            script_to_problem_mapping = problems_help.load_json()
            problem_id = script_to_problem_mapping.get(script_id, script_id)
            problem_id = base64.b64encode(problem_id.encode()).decode()
            problem = redis_client.hget("problems", problem_id)
            if problem:
                problem = Problem.from_dict(json.loads(problem))
            else:
                problem = Problem(finding.title, problem_id, finding.severity)
            update_problem(redis_client, problem, finding)
        else:
            dict_problems_findings()


def dict_problems_findings():
    redis_client = get_redis_client()
    if redis_client.exists("problems", "id_to_problem"):
        problems_data = redis_client.hgetall("problems")
        problems = {key: Problem.from_dict(json.loads(value)) for key, value in problems_data.items()}
        id_to_problem_data = redis_client.hgetall("id_to_problem")
        id_to_problem = {int(key): value for key, value in id_to_problem_data.items()}
        return problems, id_to_problem

    script_to_problem_mapping = problems_help.load_json()
    problems = {}
    id_to_problem = {}
    for finding in Finding.objects.all():
        if finding.vuln_id_from_tool and finding.severity != "Info":
            find_or_create_problem(finding, script_to_problem_mapping, problems, id_to_problem)

    if not problems:
        return problems, id_to_problem

    redis_client.delete("problems")
    redis_client.delete("id_to_problem")
    problems_data = {key: json.dumps(value.to_dict()) for key, value in problems.items()}
    id_to_problem_data = dict(id_to_problem)
    for key, value in problems_data.items():
        redis_client.hset("problems", key, value)
    for key, value in id_to_problem_data.items():
        redis_client.hset("id_to_problem", key, value)

    return problems, id_to_problem


def find_or_create_problem(finding, script_to_problem_mapping, problems, id_to_problem):
    script_id = finding.vuln_id_from_tool
    problem_id = script_to_problem_mapping.get(script_id, script_id)
    problem_id = base64.b64encode(problem_id.encode()).decode()

    if problem_id in problems:
        if finding.id not in problems[problem_id].finding_ids:
            if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[problems[problem_id].severity]:
                problems[problem_id].name = finding.title
                problems[problem_id].severity = finding.severity
            problems[problem_id].finding_ids.add(finding.id)
            problems[problem_id].script_ids.add(finding.vuln_id_from_tool)
    else:
        problems[problem_id] = Problem(finding.title, problem_id, finding.severity, {finding.vuln_id_from_tool}, {finding.id})
    id_to_problem[finding.id] = problem_id
