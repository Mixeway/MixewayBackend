package io.mixeway.domain.service.infrascan;

import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.repository.InfraScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class UpdateInfraScanService {
    private final InfraScanRepository infraScanRepository;

    public void changeStateForRunningScan(InfraScan scan){
        scan.setInQueue(false);
        scan.setRunning(true);
        infraScanRepository.save(scan);
    }
}
