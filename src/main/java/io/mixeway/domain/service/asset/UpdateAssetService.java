package io.mixeway.domain.service.asset;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.repository.AssetRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UpdateAssetService {
    private final AssetRepository assetRepository;

    public void setRequestId(InfraScan scan){
        List<Asset> assetList = scan.getInterfaces().stream().map(Interface::getAsset).collect(Collectors.toList());
        assetList.forEach( a-> a.setRequestId(scan.getRequestId()));
        assetRepository.saveAll(assetList);
    }
}
