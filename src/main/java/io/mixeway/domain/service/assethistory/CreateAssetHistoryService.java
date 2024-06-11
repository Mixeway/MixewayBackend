package io.mixeway.domain.service.assethistory;

import io.mixeway.db.entity.AssetHistory;
import io.mixeway.db.entity.Scannable;
import io.mixeway.db.repository.AssetHistoryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CreateAssetHistoryService {
    private final AssetHistoryRepository assetHistoryRepository;

    public void create(Scannable scannable, int scaVulns, int sastVulns, int dastVulns, int secretVulns, int iacVulns, int networkVulns, int crit, int high, int medium, int low) {
        assetHistoryRepository.save(new AssetHistory(scannable, scaVulns,  sastVulns,iacVulns,secretVulns,dastVulns, networkVulns, crit, high, medium, low));
    }
}
