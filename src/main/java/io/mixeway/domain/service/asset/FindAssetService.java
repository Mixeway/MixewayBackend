package io.mixeway.domain.service.asset;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.AssetRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * @author gsiewruk
 */
@RequiredArgsConstructor
@Service
public class FindAssetService {
    private final AssetRepository assetRepository;

    public List<Asset> findByRequestId(String requestId){
        return assetRepository.findByRequestId(requestId);
    }

    @Transactional
    public List<Asset> findByProject(Project project){
        return assetRepository.findByProject(project);
    }
}
