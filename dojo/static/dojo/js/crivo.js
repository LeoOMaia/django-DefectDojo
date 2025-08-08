document.addEventListener("change", function (event) {
    if (event.target.classList.contains("risk-dropdown")) {
        const dropdown = event.target;
        const findingId = dropdown.dataset.findingId;
        const risk = dropdown.value;

        const RISK_CHOICES_CLASS = ["NA", "Mild", "Moderate", "Severe", "Critical"];
        const RISK_CHOICES_NUM = ["NV", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"];

        let risk_type = "unknown";
        if (RISK_CHOICES_CLASS.includes(risk)) {
            risk_type = "class";
        } else if (RISK_CHOICES_NUM.includes(risk)) {
            risk_type = "num";
        }

        if (risk_type !== "unknown") {
            dropdown.disabled = true;

            fetch("/finding/save_assessment/", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": document.querySelector("[name=csrfmiddlewaretoken]").value,
                },
                body: JSON.stringify({ finding_id: findingId, risk: risk, risk_type: risk_type }),
            })
                .then((response) => {
                    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                    return response.json();
                })
                .then((data) => {
                    console.log("Risk saved:", data);
                })
                .catch((error) => {
                    console.error("Error saving risk:", error);
                    alert("Error saving the risk. Please try again.");
                })
                .finally(() => {
                    dropdown.disabled = false;
                });
        }
    }
});