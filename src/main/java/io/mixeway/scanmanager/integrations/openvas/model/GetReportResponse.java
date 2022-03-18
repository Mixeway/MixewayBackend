package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
@XmlRootElement(name="get_reports_response")
public class GetReportResponse {
    ReportFirstLvl reportFirstLvl;

    @XmlElement(name="report")
    public ReportFirstLvl getReportFirstLvl() {
        return reportFirstLvl;
    }

    public void setReportFirstLvl(ReportFirstLvl reportFirstLvl) {
        this.reportFirstLvl = reportFirstLvl;
    }
}
