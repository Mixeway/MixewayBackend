package io.mixeway.domain.service.securitygateway;

import io.mixeway.db.entity.SecurityGateway;
import io.mixeway.db.repository.SecurityGatewayRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindSecurityGatewayService {
    private final SecurityGatewayRepository securityGatewayRepository;

    public SecurityGateway getSecurityGateway(){
        return securityGatewayRepository.findAll().stream().findFirst().orElse(null);
    }
}
