package io.mixeway.domain.service.iaasapi;

import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.repository.IaasApiRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class DeleteIaasApiService {
    private final IaasApiRepository iaasApiRepository;

    public void delete(IaasApi iaasApi){
        iaasApiRepository.delete(iaasApi);
    }
}
