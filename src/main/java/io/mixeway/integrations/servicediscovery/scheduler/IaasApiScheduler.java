package io.mixeway.integrations.servicediscovery.scheduler;

import io.mixeway.integrations.servicediscovery.service.IaasService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * @author gsiewruk
 *
 * Scheduler for loading Assets from store IAAS platforms
 */
@Component
public class IaasApiScheduler {
    IaasService iaasApiService;

    IaasApiScheduler(IaasService iaasApiService){
        this.iaasApiService = iaasApiService;
    }

    @Scheduled(fixedDelay = 150000)
    public void synchronizeWithIaas() {
        iaasApiService.loadDataFromIaas();
    }
}
