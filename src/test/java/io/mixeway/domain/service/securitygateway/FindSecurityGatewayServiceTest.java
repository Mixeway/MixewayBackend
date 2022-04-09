package io.mixeway.domain.service.securitygateway;

import io.mixeway.db.entity.SecurityGateway;
import io.mixeway.db.repository.SecurityGatewayRepository;
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
class FindSecurityGatewayServiceTest {
    private final FindSecurityGatewayService findSecurityGatewayService;
    private final SecurityGatewayRepository securityGatewayRepository;

    @Test
    void getSecurityGateway() {
        SecurityGateway securityGateway = findSecurityGatewayService.getSecurityGateway();
        assertNotNull(securityGateway);
    }
}