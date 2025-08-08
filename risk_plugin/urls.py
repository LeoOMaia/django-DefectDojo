from django.urls import re_path

from .views import save_user_assessment, update_inferences

urlpatterns = [
    re_path(r"^save_assessment/$", save_user_assessment, name="save_user_assessment"),
    re_path(r"^update_inferences/$", update_inferences, name="update_inferences"),
]
