package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name="start_task_response")
public class StartTaskResponse {
    String reportId;

    @XmlElement(name="report_id")
    public String getReportId() {
        return reportId;
    }

    public void setReportId(String reportId) {
        this.reportId = reportId;
    }
}
