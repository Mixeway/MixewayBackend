package io.mixeway.api.project.service;

import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
class AssetServiceTest {

    @MockBean
    NetworkScanScheduler networkScanScheduler;

    @MockBean
    GlobalScheduler globalScheduler;

    @MockBean
    WebAppScheduler webAppScheduler;

    @MockBean
    CodeScheduler codeScheduler;

    @Test
    void showAssets() {
        assertFalse(true);

    }

    @Test
    void saveAsset() {
        assertFalse(true);

    }

    @Test
    void runScanForAssets() {
        assertFalse(true);

    }

    @Test
    void runAllAssetScan() {
        assertFalse(true);
    }

    @Test
    void runSingleAssetScan() {
        assertFalse(true);
    }

    @Test
    void deleteAsset() {
        assertFalse(true);
    }

    @Test
    void showInfraVulns() {
        assertFalse(true);
    }

    @Test
    void enableInfraAutoScan() {
        assertFalse(true);
    }

    @Test
    void disableInfraAutoScan() {
        assertFalse(true);
    }
}