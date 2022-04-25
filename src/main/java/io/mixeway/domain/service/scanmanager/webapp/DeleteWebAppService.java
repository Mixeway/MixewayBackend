package io.mixeway.domain.service.scanmanager.webapp;

import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.WebAppRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class DeleteWebAppService {
    private final WebAppRepository webAppRepository;

    public void delete(WebApp webApp){
        webAppRepository.delete(webApp);
    }
}
