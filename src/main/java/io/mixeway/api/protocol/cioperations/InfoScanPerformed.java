/*
 * @created  2020-08-19 : 23:53
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.protocol.cioperations;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class InfoScanPerformed {
    private String scope;
    private Long codeProjectId;
    private String branch;
    private String commitId;
}
