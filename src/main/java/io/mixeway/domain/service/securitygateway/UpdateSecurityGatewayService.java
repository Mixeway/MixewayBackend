package io.mixeway.domain.service.securitygateway;

import io.mixeway.db.entity.SecurityGateway;
import io.mixeway.db.repository.SecurityGatewayRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class UpdateSecurityGatewayService {

    private final SecurityGatewayRepository securityGatewayRepository;
    private final FindSecurityGatewayService findSecurityGatewayService;

    @Transactional
    public void update(SecurityGateway securityGatewayToUpdate) {
        SecurityGateway securityGateway = findSecurityGatewayService.getSecurityGateway();
        securityGateway.setGrade(securityGatewayToUpdate.isGrade());
        securityGateway.setCritical(securityGatewayToUpdate.getCritical());
        securityGateway.setHigh(securityGatewayToUpdate.getHigh());
        securityGateway.setMedium(securityGatewayToUpdate.getMedium());
        securityGateway.setVuln(securityGatewayToUpdate.getVuln());

    }
}
