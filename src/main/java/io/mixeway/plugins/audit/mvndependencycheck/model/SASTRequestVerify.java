package io.mixeway.plugins.audit.mvndependencycheck.model;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;

public class SASTRequestVerify {
    private Boolean valid;
    private CodeGroup cg;
    private CodeProject cp;

    public Boolean getValid() {
        return valid;
    }

    public void setValid(Boolean valid) {
        this.valid = valid;
    }

    public CodeGroup getCg() {
        return cg;
    }

    public void setCg(CodeGroup cg) {
        this.cg = cg;
    }

    public CodeProject getCp() {
        return cp;
    }

    public void setCp(CodeProject cp) {
        this.cp = cp;
    }
}
