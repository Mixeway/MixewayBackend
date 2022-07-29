package io.mixeway.domain.service.asset;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.AssetRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UpdateAssetService {
    private final AssetRepository assetRepository;
    private final FindAssetService findAssetService;

    public void setRequestId(InfraScan scan){
        List<Asset> assetList = scan.getInterfaces().stream().map(Interface::getAsset).collect(Collectors.toList());
        assetList.forEach( a-> a.setRequestId(scan.getRequestId()));
        assetRepository.saveAll(assetList);
    }

    @Transactional
    public void changeProjectForAssets(Project source, Project destination){
        for (Asset a : findAssetService.findByProject(source)){
            a.setProject(destination);
            assetRepository.saveAndFlush(a);
        }
    }
}
