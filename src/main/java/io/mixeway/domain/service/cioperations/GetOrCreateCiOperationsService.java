package io.mixeway.domain.service.cioperations;

import io.mixeway.api.cicd.model.ProjectMetadata;
import io.mixeway.db.entity.CiOperations;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Scannable;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.CiOperationsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class GetOrCreateCiOperationsService {
    private final CiOperationsRepository ciOperationsRepository;


    public CiOperations create (ProjectMetadata projectMetadata, Scannable scannable){
        Optional<CiOperations> ciOperations = ciOperationsRepository.findByCommitId(projectMetadata.getCommitId());
        if (ciOperations.isPresent()){
            return ciOperations.get();
        }
        if (scannable instanceof CodeProject){
            CiOperations operations = new CiOperations();
            operations.setCodeProject((CodeProject) scannable);
            operations.setCommitId(projectMetadata.getCommitId());
            operations.setBranch(projectMetadata.getBranch());
            operations.setInserted(new Date());
            operations.setProject(((CodeProject) scannable).getProject());
            operations.setResult("Ok");
            return ciOperationsRepository.saveAndFlush(operations);
        } else if (scannable instanceof WebApp){
            CiOperations operations = new CiOperations();
            operations.setWebapp((WebApp) scannable);
            operations.setCommitId(projectMetadata.getCommitId());
            operations.setBranch(projectMetadata.getBranch());
            operations.setInserted(new Date());
            operations.setProject(((WebApp) scannable).getProject());
            operations.setResult("Ok");
            return ciOperationsRepository.saveAndFlush(operations);
        }
        return null;
    }
}
