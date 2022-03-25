/*
 * @created  2020-08-19 : 21:04
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.cioperations.model;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotNull;

@Getter
@Setter
public class GetInfoRequest {
    @NotNull String repoUrl;
    @NotNull String branch;
    @NotNull String scope;
    Long projectId;
    String repoName;

}
