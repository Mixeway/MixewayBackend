package io.mixeway.domain.service.scanmanager.webapp;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.domain.service.scannertype.FindScannerTypeService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class VerifyWebAppScannerServiceTest {
    private final VerifyWebAppScannerService verifyWebAppScannerService;
    private final FindScannerTypeService findScannerTypeService;

    //@Test
    void canWebAppScannerBeAdded() {
        boolean status = verifyWebAppScannerService.canWebAppScannerBeAdded(findScannerTypeService.findByName(Constants.SCANNER_TYPE_ACUNETIX));
        assertTrue(status);
    }

    @Test
    void canSetPolicyForGivenScanner() {
        boolean status = verifyWebAppScannerService.canSetPolicyForGivenScanner(findScannerTypeService.findByName(Constants.SCANNER_TYPE_BURP));
        assertTrue(status);
    }
}