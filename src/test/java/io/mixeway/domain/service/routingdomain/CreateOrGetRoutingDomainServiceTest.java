package io.mixeway.domain.service.routingdomain;

import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.db.repository.RoutingDomainRepository;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class CreateOrGetRoutingDomainServiceTest {
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final RoutingDomainRepository routingDomainRepository;

    @Test
    void createOrGetRoutingDomain() {
        createOrGetRoutingDomainService.createOrGetRoutingDomain("default_created");
        RoutingDomain routingDomain = routingDomainRepository.findByName("default_created");
        assertNotNull(routingDomain);
    }
}