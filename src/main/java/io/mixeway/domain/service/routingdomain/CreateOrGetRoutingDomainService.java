/*
 * @created  2021-10-07 : 11:49
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.domain.service.routingdomain;

import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.db.repository.RoutingDomainRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CreateOrGetRoutingDomainService {
    private final RoutingDomainRepository routingDomainRepository;

    public RoutingDomain createOrGetRoutingDomain(String name){
        RoutingDomain existing = routingDomainRepository.findByName(name);
        if (existing != null){
            return existing;
        } else {
            RoutingDomain routingDomain = new RoutingDomain();
            routingDomain.setName(name);
            return routingDomainRepository.save(routingDomain);
        }
    }
    public RoutingDomain getById (Long id) {
        return routingDomainRepository.findById(id).orElse(null);
    }
}
