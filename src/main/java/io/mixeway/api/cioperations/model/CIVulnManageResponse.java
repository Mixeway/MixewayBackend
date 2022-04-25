package io.mixeway.api.cioperations.model;

import lombok.*;

import java.util.List;

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CIVulnManageResponse {
    String result;
    String commitId;
    Boolean running;
    Boolean inQueue;
    List<VulnManageResponse> vulnManageResponseList;

}
