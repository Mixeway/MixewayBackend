package io.mixeway.domain.service.scanner;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.db.repository.WebAppScanStrategyRepository;
import io.mixeway.domain.service.scannertype.FindScannerTypeService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class GetScannerService {
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final WebAppScanStrategyRepository webAppScanStrategyRepository;
    private final FindScannerTypeService findScannerTypeService;

    public Optional<Scanner> getCodeScanners() {
        return scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true).stream().findFirst();
    }
    public Scanner getScannerForWebApp(WebApp webApp){
        //WebAppScanStrategy webAppScanStrategy = webAppScanStrategyRepository.findAll().stream().findFirst().orElse(null);
        Scanner scanner = scannerRepository.findTopByScannerTypeInAndRoutingDomain(scannerTypeRepository.findByCategory(Constants.SCANER_CATEGORY_WEBAPP), webApp.getRoutingDomain());
        ;
//        if (webAppScanStrategy != null ){
//            if (webAppScanStrategy.getApiStrategy() != null && webApp.getOrigin().equals(Constants.STRATEGY_API)){
//                scanner = scannerRepository.findByScannerType(webAppScanStrategy.getApiStrategy()).stream().findFirst().orElse(null);
//            }
//            else if (webAppScanStrategy.getGuiStrategy() != null && webApp.getOrigin().equals(Constants.STRATEGY_GUI)){
//                scanner = scannerRepository.findByScannerType(webAppScanStrategy.getGuiStrategy()).stream().findFirst().orElse(null);
//            } else if (webAppScanStrategy.getScheduledStrategy() != null && webApp.getOrigin().equals(Constants.STRATEGY_SCHEDULER)){
//                scanner = scannerRepository.findByScannerType(webAppScanStrategy.getScheduledStrategy()).stream().findFirst().orElse(null);
//            } else {
//                scanner = scannerRepository.findTopByScannerTypeInAndRoutingDomain(scannerTypeRepository.findByCategory(Constants.SCANER_CATEGORY_WEBAPP), webApp.getRoutingDomain());
//            }
//        }
        return scanner;
    }
    public List<Scanner> getScannerForInfraScan(RoutingDomain routingDomain){
        return scannerRepository.findByRoutingDomainAndStatusAndScannerTypeIn(routingDomain, true, findScannerTypeService.findInfraScannerTypes());
    }
    public List<Scanner> getScannerForInfraScan(){
        return scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.findByCategory(Constants.SCANER_CATEGORY_NETWORK), true);
    }
    public Scanner getOpenSourceScanner(){
        return scannerRepository
                .findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK)).stream()
                .findFirst()
                .orElse(null);
    }
    public Scanner getScannerByType(ScannerType scannerType){
        return scannerRepository.findByScannerType(scannerType).stream().findFirst().orElse(null);
    }

    public Optional<Scanner> getScannerByApiUrlAndType(ScannerType scannerType, String url){
        return scannerRepository.findByApiUrlAndScannerType(url, scannerType);
    }

    public List<Scanner> findAll() {
        return scannerRepository.findAll();
    }
}
