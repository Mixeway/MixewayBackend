package io.mixeway.rest.project.model;

import java.util.List;

public class CodeCard {
    List<CodeModel> codeModels;
    boolean codeAutoScan;

    public List<CodeModel> getCodeModels() {
        return codeModels;
    }

    public void setCodeModels(List<CodeModel> codeModels) {
        this.codeModels = codeModels;
    }

    public boolean isCodeAutoScan() {
        return codeAutoScan;
    }

    public void setCodeAutoScan(boolean codeAutoScan) {
        this.codeAutoScan = codeAutoScan;
    }
}
