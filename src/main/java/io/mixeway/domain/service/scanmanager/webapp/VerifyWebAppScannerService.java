package io.mixeway.domain.service.scanmanager.webapp;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.db.entity.WebAppScanStrategy;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.db.repository.WebAppScanStrategyRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author gsiewruk
 */
@Service
public class VerifyWebAppScannerService {
    private final ScannerTypeRepository scannerTypeRepository;
    private final WebAppScanStrategyRepository webAppScanStrategyRepository;
    private final ScannerRepository scannerRepository;

    VerifyWebAppScannerService(ScannerTypeRepository scannerTypeRepository,
                               WebAppScanStrategyRepository webAppScanStrategyRepository,
                               ScannerRepository scannerRepository){
        this.scannerTypeRepository = scannerTypeRepository;
        this.webAppScanStrategyRepository = webAppScanStrategyRepository;
        this.scannerRepository = scannerRepository;
    }


    /**
     * Check if given ScannerType with category of WEBAPP can be added.
     * If WebAppScanStrategy contain scanner with given type, there can be only one scanner added.
     *
     * @param scannerType of scanner user is trying to add
     * @return boolean decision if it can be done
     */
    public boolean canWebAppScannerBeAdded(ScannerType scannerType){
        List<ScannerType> webScanners = scannerTypeRepository.findByCategory(Constants.SCANER_CATEGORY_WEBAPP);
        WebAppScanStrategy webAppScanStrategy = webAppScanStrategyRepository.findAll().stream().findFirst().orElse(null);
        assert webAppScanStrategy != null;
        boolean isGuiMatch = webAppScanStrategy.getGuiStrategy() != null && webAppScanStrategy.getGuiStrategy().getId().equals(scannerType.getId());
        boolean isApiMatch = webAppScanStrategy.getApiStrategy() != null && webAppScanStrategy.getApiStrategy().getId().equals(scannerType.getId());
        boolean isSchedulerMatch =webAppScanStrategy.getScheduledStrategy() != null && webAppScanStrategy.getScheduledStrategy().getId().equals(scannerType.getId());
        boolean strategyCheck = (isGuiMatch || isApiMatch || isSchedulerMatch);
        boolean scannerIsWebApp = (webScanners.contains(scannerType));
        return !(scannerIsWebApp && strategyCheck);
    }

    /**
     * Check if there are no 2 or more scanners created of given ScannerType
     * WebApp Scan Policy can be set only if there is max 1 scanner of given type
     *
     * @param scannerType of scanner to be check
     * @return boolean decision if strategy can be created or not
     */
    public boolean canSetPolicyForGivenScanner(ScannerType scannerType){
        List<ScannerType> webScanners = scannerTypeRepository.findByCategory(Constants.SCANER_CATEGORY_WEBAPP);
        if (webScanners.contains(scannerType)) {
            List<Scanner> scannersOfType = scannerRepository.findByScannerType(scannerType);
            return scannersOfType.size() <= 1;
        }
        return true;

    }
}
