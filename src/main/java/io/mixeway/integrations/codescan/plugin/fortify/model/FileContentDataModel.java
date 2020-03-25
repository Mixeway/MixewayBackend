package io.mixeway.integrations.codescan.plugin.fortify.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class FileContentDataModel {
    @JsonProperty(value = "data")
    List<FileContentModel> fileContentModel;

    public List<FileContentModel> getFileContentModel() {
        return fileContentModel;
    }

    public void setFileContentModel(List<FileContentModel> fileContentModel) {
        this.fileContentModel = fileContentModel;
    }
}
