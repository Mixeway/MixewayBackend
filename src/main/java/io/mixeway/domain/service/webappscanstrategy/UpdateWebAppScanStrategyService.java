package io.mixeway.domain.service.webappscanstrategy;

import io.mixeway.api.admin.model.WebAppScanStrategyModel;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.db.entity.WebAppScanStrategy;
import io.mixeway.db.repository.WebAppScanStrategyRepository;
import io.mixeway.domain.service.scanmanager.webapp.VerifyWebAppScannerService;
import io.mixeway.domain.service.scannertype.FindScannerTypeService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class UpdateWebAppScanStrategyService {
    private final WebAppScanStrategyRepository webAppScanStrategyRepository;
    private final FindWebAppScanStrategyService findWebAppScanStrategyService;
    private final FindScannerTypeService findScannerTypeService;
    private final VerifyWebAppScannerService verifyWebAppScannerService;

    public boolean canUpdateWebAppScanStrategy(WebAppScanStrategyModel webAppScanStrategyModel){
        WebAppScanStrategy webAppScanStrategy = findWebAppScanStrategyService.findWebAppScanStrategy();
        boolean error=false;
        if (webAppScanStrategy != null){
            if (webAppScanStrategyModel.getApiStrategy() != null){
                ScannerType apiStrategy = findScannerTypeService.findByNameIgnoreCase(webAppScanStrategyModel.getApiStrategy());
                if (verifyWebAppScannerService.canSetPolicyForGivenScanner(apiStrategy))
                    webAppScanStrategy.setApiStrategy(apiStrategy);
                else
                    error=true;
            } else {
                webAppScanStrategy.setApiStrategy(null);
            }
            if (webAppScanStrategyModel.getScheduledStrategy() != null){
                ScannerType scheduledStrategy = findScannerTypeService.findByNameIgnoreCase(webAppScanStrategyModel.getScheduledStrategy());
                if (verifyWebAppScannerService.canSetPolicyForGivenScanner(scheduledStrategy))
                    webAppScanStrategy.setScheduledStrategy(scheduledStrategy);
                else
                    error=true;
            } else {
                webAppScanStrategy.setScheduledStrategy(null);
            }
            if (webAppScanStrategyModel.getGuiStrategy() != null){
                ScannerType guiStrategy = findScannerTypeService.findByNameIgnoreCase(webAppScanStrategyModel.getGuiStrategy());
                if (verifyWebAppScannerService.canSetPolicyForGivenScanner(guiStrategy))
                    webAppScanStrategy.setGuiStrategy(guiStrategy);
                else
                    error=true;
            } else {
                webAppScanStrategy.setGuiStrategy(null);
            }
        }
        assert webAppScanStrategy != null;
        webAppScanStrategyRepository.save(webAppScanStrategy);
        return error;
    }

}
