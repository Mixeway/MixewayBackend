package io.mixeway.api.cicd.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class KicsQuery {
    @JsonProperty("query_name")
    String name;
    @JsonProperty("severity")
    String severity;
    @JsonProperty("category")
    String category;
    @JsonProperty("description")
    String description;
    @JsonProperty("files")
    List<KicsFile> files;

}
