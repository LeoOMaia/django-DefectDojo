from django.db import models


class Risk(models.Model):
    RISK_CHOICES_CLASS = [
        ("NA", "NA"),  # not available
        ("Mild", "Mild"),
        ("Moderate", "Moderate"),
        ("Severe", "Severe"),
        ("Critical", "Critical"),
    ]

    RISK_CHOICES_NUM = [
        ("NV", "NV"),  # no value
        ("0", "0"),
        ("1", "1"),
        ("2", "2"),
        ("3", "3"),
        ("4", "4"),
        ("5", "5"),
        ("6", "6"),
        ("7", "7"),
        ("8", "8"),
        ("9", "9"),
        ("10", "10"),
    ]

    finding_id = models.IntegerField()
    user_id = models.IntegerField(null=True, blank=True)
    risk_class = models.CharField(max_length=10, choices=RISK_CHOICES_CLASS)
    risk_num = models.CharField(max_length=10, choices=RISK_CHOICES_NUM)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_model_inference = models.BooleanField(default=False)

    class Meta:
        db_table = "risks"
        indexes = [
            models.Index(fields=["finding_id", "user_id"]),
        ]
