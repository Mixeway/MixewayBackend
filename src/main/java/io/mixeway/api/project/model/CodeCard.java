package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class CodeCard {
    private List<CodeModel> codeModels;
    private boolean codeAutoScan;
}
