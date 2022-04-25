package io.mixeway.domain.service.webappscanstrategy;

import io.mixeway.db.entity.WebAppScanStrategy;
import io.mixeway.db.repository.WebAppScanStrategyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindWebAppScanStrategyService {
    private final WebAppScanStrategyRepository webAppScanStrategyRepository;

    public WebAppScanStrategy findWebAppScanStrategy(){
        return webAppScanStrategyRepository.findAll().stream().findFirst().orElse(null);
    }
}
