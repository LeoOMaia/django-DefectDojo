import logging

from django.core.paginator import Paginator
from django.http import HttpRequest
from django.shortcuts import render
from django.views import View

from dojo.models import Finding
from dojo.problem.redis import dict_problems_findings
from dojo.utils import add_breadcrumb

logger = logging.getLogger(__name__)


class ListProblems(View):
    filter_name = "All"

    def get_template(self):
        return "dojo/problems_list.html"

    def get_engagement_id(self):
        return getattr(self, "engagement_id", None)

    def get_problem_id(self):
        return getattr(self, "problem_id", None)

    def add_breadcrumbs(self, request: HttpRequest, context: dict):
        add_breadcrumb(title="Problems", top_level=not len(request.GET), request=request)
        return request, context

    def order_field(self, request: HttpRequest, problems_findings_list):
        order_field = request.GET.get("o")
        if order_field:
            reverse_order = order_field.startswith("-")
            if reverse_order:
                order_field = order_field[1:]
            if order_field == "name":
                problems_findings_list = sorted(problems_findings_list, key=lambda x: x.name, reverse=reverse_order)
            elif order_field == "title":
                problems_findings_list = sorted(problems_findings_list, key=lambda x: x.title, reverse=reverse_order)
            elif order_field == "found_by":
                problems_findings_list = sorted(problems_findings_list, key=lambda x: x.found_by.count(), reverse=reverse_order)
            elif order_field == "findings_count":
                problems_findings_list = sorted(problems_findings_list, key=lambda x: len(x.finding_ids), reverse=reverse_order)
            elif order_field == "total_script_ids":
                problems_findings_list = sorted(problems_findings_list, key=lambda x: len(x.script_ids), reverse=reverse_order)
        return problems_findings_list

    def get_problems_map(self):
        problems_map, _ = dict_problems_findings()
        return problems_map

    def get_problems(self, request: HttpRequest):
        list_problem = []
        for _, problem in self.problems_map.items():
            list_problem.append(problem)

        return self.order_field(request, list_problem)

    def paginate_queryset(self, queryset, request: HttpRequest):
        page_size = request.GET.get("page_size", 25)  # Default is 25
        paginator = Paginator(queryset, page_size)
        page_number = request.GET.get("page")
        return paginator.get_page(page_number)

    def get(self, request: HttpRequest):
        self.problems_map = self.get_problems_map()
        problems = self.get_problems(request)
        paginated_problems = self.paginate_queryset(problems, request)

        context = {
            "filter_name": self.filter_name,
            "problems": paginated_problems,
        }

        request, context = self.add_breadcrumbs(request, context)
        return render(request, self.get_template(), context)


class ListOpenProblems(ListProblems):
    filter_name = "Open"

    def get_problems(self, request: HttpRequest):
        list_problem = []
        for _, problem in self.problems_map.items():
            if any(Finding.objects.filter(id=finding_id, active=True) for finding_id in problem.finding_ids):
                list_problem.append(problem)
        return self.order_field(request, list_problem)


class ListClosedProblems(ListProblems):
    filter_name = "Closed"

    def get_problems(self, request: HttpRequest):
        list_problem = []
        for _, problem in self.problems_map.items():
            if not any(Finding.objects.filter(id=finding_id, active=True) for finding_id in problem.finding_ids):
                list_problem.append(problem)
        return self.order_field(request, list_problem)


class ProblemFindings(ListProblems):
    def get_template(self):
        return "dojo/problem_findings.html"

    def get_findings(self, request: HttpRequest):
        problem = self.problems_map.get(self.problem_id)
        list_findings = problem.finding_ids
        findings = Finding.objects.filter(id__in=list_findings)
        return problem.name, self.order_field(request, findings)

    def get(self, request: HttpRequest, problem_id: int):
        self.problem_id = problem_id
        self.problems_map = self.get_problems_map()
        problem_name, findings = self.get_findings(request)
        paginated_findings = self.paginate_queryset(findings, request)

        context = {
            "problem": problem_name,
            "findings": paginated_findings,
        }

        request, context = self.add_breadcrumbs(request, context)
        return render(request, self.get_template(), context)
