package io.mixeway.domain.service.securitygateway;

import io.mixeway.db.entity.SecurityGateway;
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
class UpdateSecurityGatewayServiceTest {
    private final UpdateSecurityGatewayService updateSecurityGatewayService;
    private final FindSecurityGatewayService findSecurityGatewayService;

    @Test
    void update() {
        SecurityGateway securityGateway = new SecurityGateway();
        securityGateway.setGrade(true);
        securityGateway.setHigh(10);
        securityGateway.setCritical(20);
        updateSecurityGatewayService.update(securityGateway);
        SecurityGateway gateway = findSecurityGatewayService.getSecurityGateway();
        assertTrue(gateway.isGrade());
        assertEquals(10, gateway.getHigh());
        assertEquals(20, gateway.getCritical());
    }
}