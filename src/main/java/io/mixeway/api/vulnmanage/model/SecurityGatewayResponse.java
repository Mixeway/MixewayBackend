/*
 * @created  2021-01-21 : 13:57
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.vulnmanage.model;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Builder
@Getter
@Setter
@NoArgsConstructor
public class SecurityGatewayResponse {

    private boolean isSecurityPolicyMet;
    private String policyResponse;
    private List<Vuln> vulnList;

    public SecurityGatewayResponse(boolean isSecurityPolicyMet, String policyResponse, List<Vuln> vulnList){
        this.isSecurityPolicyMet = isSecurityPolicyMet;
        this.policyResponse = policyResponse;
        this.vulnList = vulnList;
    }

}
