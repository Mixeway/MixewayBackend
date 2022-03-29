package io.mixeway.domain.service.routingdomain;

import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.db.repository.RoutingDomainRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindRoutingDomainService {
    private final RoutingDomainRepository routingDomainRepository;


    public Optional<RoutingDomain> findById(Long id) {
        return routingDomainRepository.findById(id);
    }

    public RoutingDomain findByName(String defaultRoutingDomain) {
        return routingDomainRepository.findByName(defaultRoutingDomain);
    }

    public List<RoutingDomain> findAll() {
        return routingDomainRepository.findAll();
    }
}
