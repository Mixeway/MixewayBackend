package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeGroupRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindCodeGroupService {
    private final CodeGroupRepository codeGroupRepository;

    public Optional<CodeGroup> findCodeGroup(Project project, String codeGroupName){
        return codeGroupRepository.findByProjectAndName(project, codeGroupName);
    }
    public List<CodeGroup> findCodeGroupsWithScanIds() {
        return codeGroupRepository.findByScanidNotNull();
    }
}
