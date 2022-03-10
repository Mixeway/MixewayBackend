package io.mixeway.scanmanager.integrations.fortify.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class FileContentDataModel {
    @JsonProperty(value = "data")
    List<FileContentModel> fileContentModel;

}
