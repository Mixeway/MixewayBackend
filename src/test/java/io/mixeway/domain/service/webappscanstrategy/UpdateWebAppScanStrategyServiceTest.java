package io.mixeway.domain.service.webappscanstrategy;

import io.mixeway.api.admin.model.WebAppScanStrategyModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.WebAppScanStrategy;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class UpdateWebAppScanStrategyServiceTest {
    private final UpdateWebAppScanStrategyService updateWebAppScanStrategyService;
    private final FindWebAppScanStrategyService findWebAppScanStrategyService;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;

    @Test
    void canUpdateWebAppScanStrategy() {
        Scanner scanner = new Scanner();
        scanner.setStatus(true);
        scanner.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_BURP));
        scannerRepository.save(scanner);
        WebAppScanStrategyModel webAppScanStrategyModel = new WebAppScanStrategyModel();
        webAppScanStrategyModel.setApiStrategy(Constants.SCANNER_TYPE_BURP);
        boolean updated = updateWebAppScanStrategyService.canUpdateWebAppScanStrategy(webAppScanStrategyModel);
        assertFalse(updated);
        WebAppScanStrategy webAppScanStrategy = findWebAppScanStrategyService.findWebAppScanStrategy();
        assertEquals(Constants.SCANNER_TYPE_BURP, webAppScanStrategy.getApiStrategy().getName());
    }
}