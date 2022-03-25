package io.mixeway.domain.service.routingdomain;

import io.mixeway.db.repository.RoutingDomainRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class DeleteRoutingDomainService {
    private final RoutingDomainRepository routingDomainRepository;

    public void deleteById(Long id){
        routingDomainRepository.deleteById(id);
    }
}
