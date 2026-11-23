function getCrivoCsrfToken() {
    const input = document.querySelector("[name=csrfmiddlewaretoken]");
    if (input && input.value) {
        return input.value;
    }
    const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
}

function syncRiskSelectpicker(dropdown, { clearModelStyle = false } = {}) {
    dropdown.disabled = false;

    if (clearModelStyle) {
        dropdown.removeAttribute("data-style");
        dropdown.dataset.fromModel = "false";
        dropdown.classList.remove("fa-asterisk");

        const container = dropdown.closest(".risk-cell") || dropdown.parentElement;
        const confirmBtn = container ? container.querySelector(".confirm-risk-btn") : null;
        if (confirmBtn) {
            confirmBtn.remove();
        }
    }

    if (!window.jQuery || typeof window.jQuery(dropdown).selectpicker !== "function") {
        return;
    }

    const $select = window.jQuery(dropdown);
    const sp = $select.data("selectpicker");
    if (clearModelStyle) {
        $select.removeData("style");
        if (sp && sp.options) {
            sp.options.style = "btn-default";
        }
        $select.selectpicker("setStyle", "fa-asterisk", "remove");
        $select.selectpicker("setStyle", "btn-default", "add");
    }
    $select.selectpicker("refresh");

    const updatedSp = $select.data("selectpicker");
    if (updatedSp) {
        if (updatedSp.$newElement) {
            updatedSp.$newElement.removeClass("open disabled");
        }
        if (updatedSp.$bsContainer) {
            updatedSp.$bsContainer.removeClass("open");
        }
        if (updatedSp.$button) {
            updatedSp.$button.removeClass("disabled").prop("disabled", false).attr("aria-expanded", "false");
            if (clearModelStyle) {
                updatedSp.$button.removeClass("fa-asterisk").addClass("btn-default");
            }
        }
    }
    $select.closest(".bootstrap-select").removeClass("open disabled");
}

function saveRiskAssessment(dropdown, risk, confirmBtn = null) {
    const findingId = dropdown.dataset.findingId;
    const RISK_CHOICES_CLASS = ["NA", "Mild", "Moderate", "Severe", "Critical"];
    const RISK_CHOICES_NUM = ["NV", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"];

    let risk_type = "unknown";
    if (RISK_CHOICES_CLASS.includes(risk)) {
        risk_type = "class";
    } else if (RISK_CHOICES_NUM.includes(risk)) {
        risk_type = "num";
    }

    if (risk_type === "unknown" || dropdown.dataset.saving === "1") {
        return;
    }

    dropdown.dataset.saving = "1";
    if (confirmBtn) {
        confirmBtn.disabled = true;
    }
    let savedOk = false;

    // Ensure the bootstrap-select menu closes cleanly even if body click handlers toggle it
    setTimeout(() => syncRiskSelectpicker(dropdown), 0);

    fetch("/finding/save_assessment/", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCrivoCsrfToken(),
        },
        body: JSON.stringify({ finding_id: findingId, risk: risk, risk_type: risk_type }),
    })
        .then((response) => {
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return response.json();
        })
        .then((data) => {
            savedOk = true;
            console.log("Risk saved:", data);
        })
        .catch((error) => {
            console.error("Error saving risk:", error);
            if (confirmBtn) {
                confirmBtn.disabled = false;
            }
            alert("Error saving the risk. Please try again.");
        })
        .finally(() => {
            delete dropdown.dataset.saving;
            syncRiskSelectpicker(dropdown, { clearModelStyle: savedOk });
        });
}

document.addEventListener("change", function (event) {
    if (event.target.matches("select.risk-dropdown")) {
        saveRiskAssessment(event.target, event.target.value);
    }
});

document.addEventListener("click", function (event) {
    const confirmBtn = event.target.closest(".confirm-risk-btn");
    if (!confirmBtn) {
        return;
    }
    event.preventDefault();
    const cell = confirmBtn.closest(".risk-cell");
    const dropdown = cell
        ? cell.querySelector("select.risk-dropdown")
        : document.querySelector(`select.risk-dropdown[data-finding-id="${confirmBtn.dataset.findingId}"]`);
    if (dropdown && dropdown.value && dropdown.value !== "NA") {
        saveRiskAssessment(dropdown, dropdown.value, confirmBtn);
    }
});