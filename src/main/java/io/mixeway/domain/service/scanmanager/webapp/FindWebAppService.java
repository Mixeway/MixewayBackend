package io.mixeway.domain.service.scanmanager.webapp;

import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.WebAppRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@RequiredArgsConstructor
@Service
public class FindWebAppService {
    private final WebAppRepository webAppRepository;

    public List<WebApp> findRunningWebApps(){
        return webAppRepository.findByRunning(true);
    }

    public List<WebApp> findInQueueWebApps() {
        return webAppRepository.findByInQueue(true);
    }
    public Optional<WebApp> findById(Long id){
        return webAppRepository.findById(id);
    }
}
