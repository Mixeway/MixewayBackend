/*
 * @created  2021-03-23 : 17:36
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.domain.service.cioperations;

import io.mixeway.api.cicd.model.ProjectMetadata;
import io.mixeway.api.cioperations.model.CIVulnManageResponse;
import io.mixeway.api.cioperations.service.CiOperationsService;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.CiOperations;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Scan;
import io.mixeway.db.repository.CiOperationsRepository;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.utils.SecurityGatewayEntry;
import io.mixeway.utils.SecurityQualityGateway;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UpdateCiOperationsService {

    private final SecurityQualityGateway securityQualityGateway;
    private final CiOperationsRepository ciOperationsRepository;
    private final VulnTemplate vulnTemplate;
    private final GetOrCreateCiOperationsService getOrCreateCiOperationsService;


    @Transactional
    public void updateCiOperationsForOpenSource(CodeProject codeProject){
        SecurityGatewayEntry gateway = securityQualityGateway.buildGatewayResponse(vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject));
        Optional<CiOperations> ciOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject,codeProject.getCommitid());
        if (ciOperations.isPresent()){
            ciOperations.get().setOpenSourceCrit(gateway.getOsCritical());
            ciOperations.get().setOpenSourceHigh(gateway.getOsHigh());
            ciOperations.get().setOpenSourceScan(true);
            ciOperations.get().setResult(gateway.isPassed() ? "Ok":"Not Ok");
        }
    }
    @Transactional
    public void updateCiOperationsForOpenSource(CodeProject codeProject, ProjectMetadata projectMetadata){
        SecurityGatewayEntry gateway = securityQualityGateway.buildGatewayResponse(vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject));
        Optional<CiOperations> ciOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject, projectMetadata.getCommitId());
        CiOperations operations = getOrCreateCiOperationsService.create(projectMetadata,codeProject);
    }
    @Transactional
    public void updateCiOperationsForSAST(CodeProject codeProject){
        SecurityGatewayEntry gateway = securityQualityGateway.buildGatewayResponse(vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject));
        Optional<CiOperations> ciOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject,codeProject.getCommitid());
        if (ciOperations.isPresent()){
            ciOperations.get().setSastCrit(gateway.getSastCritical());
            ciOperations.get().setSastHigh(gateway.getSastHigh());
            ciOperations.get().setSastScan(true);
            ciOperations.get().setResult(gateway.isPassed() ? "Ok":"Not Ok");
        }
    }
    public void updateCiOperations(CiOperations ciOperations, CIVulnManageResponse ciVulnManageResponse){
        ciOperations.setEnded(new Date());
        ciOperations.setResult(ciVulnManageResponse.getResult());
        ciOperationsRepository.save(ciOperations);
    }

    @Transactional
    public void updateCiOperations(CiOperations ciOperations, SecurityGatewayEntry securityGatewayEntry, CodeProject codeProject){
        ciOperations.setResult(securityGatewayEntry.isPassed()?"Ok":"Not Ok");
        ciOperations.setOpenSourceScan(StringUtils.isNotBlank(codeProject.getdTrackUuid()));
        ciOperations.setSastScan(securityGatewayEntry.countSastVulns() > 0);
        ciOperations.setOpenSourceHigh(securityGatewayEntry.getOsHigh());
        ciOperations.setOpenSourceCrit(securityGatewayEntry.getOsCritical());
        ciOperations.setSastCrit(securityGatewayEntry.getSastCritical());
        ciOperations.setSastHigh(securityGatewayEntry.getSastHigh());
        ciOperationsRepository.save(ciOperations);
    }

    public void putScanOnAPipeline(CiOperations ciOperations, Scan scan, SecurityGatewayEntry securityGatewayEntry){
        if (scan.getType().equals(Constants.SECRET_LABEL)){
            ciOperations.setSecretScan(scan);
        } else if (scan.getType().equals(Constants.IAC_LABEL)){
            ciOperations.setIacScan(scan);
        } else if (scan.getType().equals(Constants.SCA_LABEL)){
            ciOperations.setScaScan(scan);
        } else if (scan.getType().equals(Constants.SAST_LABEL)){
            ciOperations.setCodeScan(scan);
        } else if (scan.getType().equals(Constants.DAST_LABEL)){
            ciOperations.setDastScan(scan);
        }
        ciOperations.setResult(securityGatewayEntry.isPassed()?"Ok":"Not Ok");

        ciOperationsRepository.saveAndFlush(ciOperations);
    }
}
