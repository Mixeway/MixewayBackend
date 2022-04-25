package io.mixeway.domain.service.intf;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.InfraScanRepository;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.ProjectVulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class DeleteInterfaceService {
    private final InterfaceRepository interfaceRepository;
    private final InfraScanRepository infraScanRepository;
    private final AssetRepository assetRepository;
    private final ProjectVulnerabilityRepository projectVulnerabilityRepository;

    @Transactional
    public void delete(Optional<Interface> interf){
        if (interf.isPresent()) {
            List<InfraScan> infraScans = infraScanRepository.findByProject(interf.get().getAsset().getProject());
            for (InfraScan infraScan : infraScans){
                if (infraScan.getInterfaces().contains(interf.get())){
                    infraScan.getInterfaces().remove(interf.get());
                    infraScanRepository.save(infraScan);
                }
            }
            List<ProjectVulnerability> projectVulnerabilities = projectVulnerabilityRepository.findByAnInterface(interf.get());
            projectVulnerabilityRepository.deleteAll(projectVulnerabilities);
        }
        interf.ifPresent(i -> i.setAsset(null));
        interf.ifPresent(interfaceRepository::save);
        interf.ifPresent(interfaceRepository::delete);
    }
}
