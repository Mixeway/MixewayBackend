package io.mixeway.domain.service.scan;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.InfraScanRepository;
import io.mixeway.db.repository.WebAppRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class GetScanNumberService {
    private final WebAppRepository webAppRepository;
    private final InfraScanRepository infraScanRepository;
    private final CodeProjectRepository codeProjectRepository;


    public Long getNumberOfScansInQueue() {
        return (webAppRepository.countByInQueue(true) + codeProjectRepository.countByInQueue(true) + infraScanRepository.countByInQueue(true));
    }
    public Long getNumberOfScansRunning() {
        return (webAppRepository.countByRunning(true) + codeProjectRepository.countByRunning(true) + infraScanRepository.countByRunning(true));
    }
}
