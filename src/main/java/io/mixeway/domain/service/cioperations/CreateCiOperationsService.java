package io.mixeway.domain.service.cioperations;

import io.mixeway.api.cicd.model.LoadSCA;
import io.mixeway.api.cicd.model.ProjectMetadata;
import io.mixeway.api.protocol.cioperations.InfoScanPerformed;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CiOperationsRepository;
import io.mixeway.scanmanager.model.SASTRequestVerify;
import io.mixeway.utils.SecurityGatewayEntry;
import lombok.RequiredArgsConstructor;
import org.aspectj.apache.bcel.classfile.Code;
import org.checkerframework.checker.nullness.Opt;
import org.checkerframework.checker.units.qual.C;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class CreateCiOperationsService {
    private final CiOperationsRepository ciOperationsRepository;
    private final FindCiOperationsService findCiOperationsService;

    public void create(SASTRequestVerify verifyRequest, Project project, String commitId){
        CiOperations newOperation = new CiOperations();
        newOperation.setProject(project);
        newOperation.setCodeProject(verifyRequest.getCp());
        newOperation.setCommitId(commitId);
        if (!findCiOperationsService.findByCodeProjectAndCommitId(verifyRequest.getCp(), commitId).isPresent()) {
            ciOperationsRepository.saveAndFlush(newOperation);
        }
    }


    public CiOperations create(CodeProject codeProject, InfoScanPerformed infoScanPerformed) {
        Optional<CiOperations> ciOperations = findCiOperationsService.findByCodeProjectAndCommitId(codeProject, infoScanPerformed.getCommitId());
        return ciOperations.orElseGet(() -> ciOperationsRepository.save(new CiOperations(codeProject, infoScanPerformed)));
    }
    public CiOperations create(CodeProject codeProject, LoadSCA loadSca) {
        Optional<CiOperations> ciOperations = findCiOperationsService.findByCodeProjectAndCommitId(codeProject, loadSca.getCommitId());
        return ciOperations.orElseGet(() -> ciOperationsRepository.save(new CiOperations(codeProject, loadSca)));
    }
    public CiOperations create(SecurityGatewayEntry securityGatewayEntry, CodeProject codeProject, Optional<CiOperations> optionalCiOperations){
        CiOperations ciOperations = optionalCiOperations.orElseGet(CiOperations::new);
        ciOperations.setResult(securityGatewayEntry.isPassed() ? "Ok" : "Not Ok");
        ciOperations.setCodeProject(codeProject);
        ciOperations.setInserted(new Date());
        ciOperations.setEnded(new Date());
        ciOperations.setOpenSourceScan(true);
        ciOperations.setSastScan(true);
        ciOperations.setProject(codeProject.getProject());
        ciOperations.setCommitId(codeProject.getCommitid()!=null? codeProject.getCommitid() : "unknown");
        ciOperations.setSastHigh(securityGatewayEntry.getSastHigh());
        ciOperations.setSastCrit(securityGatewayEntry.getSastCritical());
        ciOperations.setOpenSourceCrit(securityGatewayEntry.getOsCritical());
        ciOperations.setOpenSourceHigh(securityGatewayEntry.getOsHigh());

        return ciOperationsRepository.saveAndFlush(ciOperations);
    }

}
