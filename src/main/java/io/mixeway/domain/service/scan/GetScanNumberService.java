package io.mixeway.domain.service.scan;

import io.mixeway.db.repository.CodeGroupRepository;
import io.mixeway.db.repository.NessusScanRepository;
import io.mixeway.db.repository.WebAppRepository;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
public class GetScanNumberService {
    private WebAppRepository webAppRepository;
    private NessusScanRepository nessusScanRepository;
    private CodeGroupRepository codeGroupRepository;

    public GetScanNumberService (WebAppRepository webAppRepository, NessusScanRepository nessusScanRepository, CodeGroupRepository codeGroupRepository) {
        this.webAppRepository = webAppRepository;
        this.nessusScanRepository = nessusScanRepository;
        this.codeGroupRepository = codeGroupRepository;
    }

    public Long getNumberOfScansInQueue() {
        return (webAppRepository.countByInQueue(true) + codeGroupRepository.countByInQueue(true) + nessusScanRepository.countByInQueue(true));
    }
    public Long getNumberOfScansRunning() {
        return (webAppRepository.countByRunning(true) + codeGroupRepository.countByRunning(true) + nessusScanRepository.countByRunning(true));
    }
}
