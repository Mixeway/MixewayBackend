/*
 * @created  2021-03-23 : 17:36
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.domain.service.cioperations;

import io.mixeway.db.entity.CiOperations;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.repository.CiOperationsRepository;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.pojo.SecurityGatewayEntry;
import io.mixeway.pojo.SecurityQualityGateway;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class UpdateCiOperations {

    private final SecurityQualityGateway securityQualityGateway;
    private final CiOperationsRepository ciOperationsRepository;
    private final VulnTemplate vulnTemplate;
    public UpdateCiOperations(SecurityQualityGateway securityQualityGateway, CiOperationsRepository ciOperationsRepository,
                              VulnTemplate vulnTemplate){
        this.ciOperationsRepository = ciOperationsRepository;
        this.securityQualityGateway = securityQualityGateway;
        this.vulnTemplate = vulnTemplate;
    }

    @Transactional
    public void updateCiOperationsForOpenSource(CodeProject codeProject){
        SecurityGatewayEntry gateway = securityQualityGateway.buildGatewayResponse(vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject));
        Optional<CiOperations> ciOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject,codeProject.getCommitid());
        if (ciOperations.isPresent()){
            ciOperations.get().setOpenSourceCrit(gateway.getOsCritical());
            ciOperations.get().setOpenSourceHigh(gateway.getOsHigh());
            ciOperations.get().setResult(gateway.isPassed() ? "Ok":"Not Ok");
        }
    }
    @Transactional
    public void updateCiOperationsForSAST(CodeProject codeProject){
        SecurityGatewayEntry gateway = securityQualityGateway.buildGatewayResponse(vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject));
        Optional<CiOperations> ciOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject,codeProject.getCommitid());
        if (ciOperations.isPresent()){
            ciOperations.get().setOpenSourceCrit(gateway.getSastCritical());
            ciOperations.get().setOpenSourceHigh(gateway.getSastHigh());
            ciOperations.get().setResult(gateway.isPassed() ? "Ok":"Not Ok");
        }
    }
}
