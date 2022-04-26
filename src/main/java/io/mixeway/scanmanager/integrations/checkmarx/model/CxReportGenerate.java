package io.mixeway.scanmanager.integrations.checkmarx.model;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class CxReportGenerate {
    private String reportType;
    private String scanId;

    public CxReportGenerate(CodeProject codeGroup){
        this.reportType = Constants.CX_REPORT_TYPE;
        this.scanId = codeGroup.getScanid();
    }
    public CxReportGenerate(){}

}
