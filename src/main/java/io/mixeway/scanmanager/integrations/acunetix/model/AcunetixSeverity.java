package io.mixeway.scanmanager.integrations.acunetix.model;

import static java.util.Arrays.stream;

public enum AcunetixSeverity {

    ACUNETIX_SEVERITY_INFO(0, "Info"),
    ACUNETIX_SEVERITY_LOW(1, "Low"),
    ACUNETIX_SEVERITY_MEDIUM(2, "Medium"),
    ACUNETIX_SEVERITY_HIGH(3, "High");

    private final int severityNumberCode;
    private final String severityDescription;

    AcunetixSeverity(int severityNumberCode, String severityDescription) {
        this.severityNumberCode = severityNumberCode;
        this.severityDescription = severityDescription;
    }

    public static String resolveSeverity(int severityNumberCode) {
        return stream(values())
                .filter(severity-> severityNumberCode == severity.severityNumberCode)
                .findFirst()
                .map(severity -> severity.severityDescription)
                .orElse(ACUNETIX_SEVERITY_HIGH.severityDescription);
    }

    public String getSeverityDescription() {
        return severityDescription;
    }
}
