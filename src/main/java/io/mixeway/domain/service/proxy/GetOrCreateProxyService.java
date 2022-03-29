package io.mixeway.domain.service.proxy;

import io.mixeway.db.entity.Proxies;
import io.mixeway.db.repository.ProxiesRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class GetOrCreateProxyService {
    private final ProxiesRepository proxiesRepository;

    public Proxies getOrCreateProxies(Proxies proxies){
        return proxiesRepository.saveAndFlush(proxies);
    }
    public Optional<Proxies> findById(Long id){
        return proxiesRepository.findById(id);
    }

    public List<Proxies> findAll() {
        return proxiesRepository.findAll();
    }
}
