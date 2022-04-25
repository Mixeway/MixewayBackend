/*
 * @created  2020-08-19 : 23:53
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.cioperations.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class InfoScanPerformed {
    String scope;
    Long codeProjectId;
    String branch;
    String commitId;

}
