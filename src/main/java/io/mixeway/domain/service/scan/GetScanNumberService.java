package io.mixeway.domain.service.scan;

import io.mixeway.db.repository.CodeGroupRepository;
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
    private final CodeGroupRepository codeGroupRepository;


    public Long getNumberOfScansInQueue() {
        return (webAppRepository.countByInQueue(true) + codeGroupRepository.countByInQueue(true) + infraScanRepository.countByInQueue(true));
    }
    public Long getNumberOfScansRunning() {
        return (webAppRepository.countByRunning(true) + codeGroupRepository.countByRunning(true) + infraScanRepository.countByRunning(true));
    }
}
