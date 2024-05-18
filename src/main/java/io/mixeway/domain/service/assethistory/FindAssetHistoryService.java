package io.mixeway.domain.service.assethistory;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.AssetHistoryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class FindAssetHistoryService {
    private final AssetHistoryRepository assetHistoryRepository;

    public List<AssetHistory> getAssetHistory(Scannable scannable){
        if (scannable instanceof CodeProject){
            return assetHistoryRepository.findByCodeProject((CodeProject) scannable);
        } else if (scannable instanceof WebApp){
            return assetHistoryRepository.findByWebapp((WebApp) scannable);
        } else if(scannable instanceof Interface){
            return assetHistoryRepository.findByInterfaceObj((Interface) scannable);
        } else {
            return new ArrayList<>();
        }
    }
}
