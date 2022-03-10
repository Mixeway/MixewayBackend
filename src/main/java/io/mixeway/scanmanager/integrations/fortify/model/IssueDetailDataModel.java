package io.mixeway.scanmanager.integrations.fortify.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class IssueDetailDataModel {
    @JsonProperty(value = "data")
    private IssueDetailModel issueDetailModel;
}
