package io.mixeway.domain.service.proxy;

import io.mixeway.db.repository.ProxiesRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class DeleteProxyService {
    private final ProxiesRepository proxiesRepository;

    public void deleteById(Long id){
        proxiesRepository.deleteById(id);
    }
}
