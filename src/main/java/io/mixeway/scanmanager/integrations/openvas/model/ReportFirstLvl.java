package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
@XmlRootElement(name="report")
public class ReportFirstLvl {
    ReportSecondLvl reportSecondLvl;

    @XmlElement(name="report")
    public ReportSecondLvl getReportSecondLvl() {
        return reportSecondLvl;
    }

    public void setReportSecondLvl(ReportSecondLvl reportSecondLvl) {
        this.reportSecondLvl = reportSecondLvl;
    }
}
