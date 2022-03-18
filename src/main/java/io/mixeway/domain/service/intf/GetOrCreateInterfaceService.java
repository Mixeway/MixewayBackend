package io.mixeway.domain.service.intf;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.domain.service.asset.GetOrCreateAssetService;
import io.mixeway.scanmanager.model.AssetToCreate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class GetOrCreateInterfaceService {
    private final InterfaceRepository interfaceRepository;
    private final GetOrCreateAssetService getOrCreateAssetService;
    private final InterfaceOperations interfaceOperations;


}
