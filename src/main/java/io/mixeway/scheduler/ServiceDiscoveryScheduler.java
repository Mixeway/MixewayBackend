package io.mixeway.scheduler;

import io.mixeway.servicediscovery.service.IaasService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * @author gsiewruk
 *
 * Scheduler for loading Assets from store IAAS platforms
 */
@Component
public class ServiceDiscoveryScheduler {
    IaasService iaasApiService;

    ServiceDiscoveryScheduler(IaasService iaasApiService){
        this.iaasApiService = iaasApiService;
    }

    @Scheduled(fixedDelay = 150000)
    public void synchronizeWithIaas() {
        iaasApiService.loadDataFromIaas();
    }
}
