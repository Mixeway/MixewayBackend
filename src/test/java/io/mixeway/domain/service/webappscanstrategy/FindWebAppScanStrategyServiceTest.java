package io.mixeway.domain.service.webappscanstrategy;

import io.mixeway.db.entity.WebAppScanStrategy;
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
class FindWebAppScanStrategyServiceTest {
    private final FindWebAppScanStrategyService findWebAppScanStrategyService;

    @Test
    void findWebAppScanStrategy() {
        WebAppScanStrategy webAppScanStrategy = findWebAppScanStrategyService.findWebAppScanStrategy();
        assertNotNull(webAppScanStrategy);
    }
}