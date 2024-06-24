package io.mixeway.api.cicd.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class KicsFile {
    @JsonProperty("file_name")
    String name;
    @JsonProperty("line")
    int line;
    @JsonProperty("expected_value")
    String expectedValue;
    @JsonProperty("actual_value")
    String actualValue;
}
