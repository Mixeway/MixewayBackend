package io.mixeway.domain.service.iaasapi;

import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.repository.IaasApiRepository;
import io.mixeway.db.repository.IaasApiTypeRepisotory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class UpdateIaasApiService {
    private final IaasApiTypeRepisotory iaasApiTypeRepisotory;
    private final IaasApiRepository iaasApiRepository;

    public void enable(IaasApi iaasApi) {
        iaasApi.setEnabled(true);
        iaasApiRepository.save(iaasApi);
    }

    public void disable(IaasApi iaasApi) {
        iaasApi.setEnabled(false);
        iaasApiRepository.save(iaasApi);
    }
}
