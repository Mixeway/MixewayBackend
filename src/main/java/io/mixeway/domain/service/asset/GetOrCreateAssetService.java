package io.mixeway.domain.service.asset;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.scanmanager.model.AssetToCreate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class GetOrCreateAssetService {
    private final AssetRepository assetRepository;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;


    public Asset getOrCreateAsset(AssetToCreate atc, Project project, String origin) {
        //Optional<Asset> asset = assetRepository.findByProjectAndName(project,atc.getHostname() != null ? atc.getHostname() : atc.getIp());
        Optional<Asset> asset = assetRepository.findAssetByProjectAndPrivateIp(project.getId(), atc.getIp());
        if (asset.isPresent()) {
            Asset a = asset.get();
            a.setName(atc.getHostname() != null ? atc.getHostname() : atc.getIp());
            a.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain(atc.getRoutingDomain()));
            return asset.get();
        } else {
            Asset a = new Asset();
            a.setName(atc.getHostname() != null ? atc.getHostname() : atc.getIp());
            a.setActive(true);
            a.setProject(project);
            a.setOrigin(origin);
            a.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain(atc.getRoutingDomain()));
            return assetRepository.saveAndFlush(a);
        }

    }

    public Asset getOrCreateAsset(String name, RoutingDomain routingDomain, Project project) {
        return assetRepository.save(new Asset(name,routingDomain, project));
    }
}
