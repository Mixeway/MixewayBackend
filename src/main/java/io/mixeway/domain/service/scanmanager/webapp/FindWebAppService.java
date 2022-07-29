package io.mixeway.domain.service.scanmanager.webapp;

import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.WebAppRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

    public List<WebApp> findByRequestId(String requestId) {
        return webAppRepository.findByRequestId(requestId);
    }

    public List<WebApp> findByRunning(boolean b) {
        return webAppRepository.findByRunning(b);
    }

    public List<WebApp> findByInQueue(boolean b) {
        return webAppRepository.findByInQueue(b);
    }

    public Optional<WebApp> findByProjectAndRul(Project project, String url) {
        return webAppRepository.findByProjectAndUrl(project,url);
    }
    @Transactional
    public List<WebApp> findByProject(Project project){
        return webAppRepository.findByProject(project);
    }
}
