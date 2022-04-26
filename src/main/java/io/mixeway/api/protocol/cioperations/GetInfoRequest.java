/*
 * @created  2020-08-19 : 21:04
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.protocol.cioperations;

import lombok.*;

import javax.validation.constraints.NotNull;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class GetInfoRequest {
    @NotNull private String repoUrl;
    @NotNull private String branch;
    @NotNull private String scope;
    private Long projectId;
    private String repoName;
}
