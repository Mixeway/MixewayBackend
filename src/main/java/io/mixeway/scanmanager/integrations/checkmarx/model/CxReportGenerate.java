package io.mixeway.scanmanager.integrations.checkmarx.model;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeGroup;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CxReportGenerate {
    private String reportType;
    private String scanId;

    public CxReportGenerate(CodeGroup codeGroup){
        this.reportType = Constants.CX_REPORT_TYPE;
        this.scanId = codeGroup.getScanid();
    }
    public CxReportGenerate(){}

}
