package io.mixeway.domain.service.infrascan;

import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.InfraScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindInfraScanService {
    private final InfraScanRepository infraScanRepository;

    public List<InfraScan> findByProjectAndRunning(Project project){
        return infraScanRepository.findByProjectAndIsAutomatic(project,false).stream().filter(InfraScan::getRunning).collect(Collectors.toList());
    }
}
