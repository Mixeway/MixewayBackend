package io.mixeway.domain.service.iaasapi;

import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.entity.IaasApiType;
import io.mixeway.db.repository.IaasApiRepository;
import io.mixeway.db.repository.IaasApiTypeRepisotory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class GetOrCreateIaasApiService {
    private final IaasApiTypeRepisotory iaasApiTypeRepisotory;
    private final IaasApiRepository iaasApiRepository;

    public List<IaasApiType> findAllTypes() {
        return iaasApiTypeRepisotory.findAll();
    }
}
