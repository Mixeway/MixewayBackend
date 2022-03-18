package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.*;


@XmlRootElement(name="commands_response")
@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
public class ComandResponseGetReport {
    String status;
    GetReportResponse getReportResponse;

    @XmlElement(name="get_reports_response")
    public GetReportResponse getGetReportResponse() {
        return getReportResponse;
    }

    public void setGetReportResponse(GetReportResponse getReportResponse) {
        this.getReportResponse = getReportResponse;
    }


    @XmlAttribute(name="status")
    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
