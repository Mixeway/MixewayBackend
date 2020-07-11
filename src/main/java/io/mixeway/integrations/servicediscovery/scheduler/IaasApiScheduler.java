package io.mixeway.integrations.servicediscovery.scheduler;

import io.mixeway.integrations.servicediscovery.service.IaasApiService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * @author gsiewruk
 *
 * Scheduler for loading Assets from store IAAS platforms
 */
@Component
public class IaasApiScheduler {
    IaasApiService iaasApiService;

    IaasApiScheduler(IaasApiService iaasApiService){
        this.iaasApiService = iaasApiService;
    }

    @Scheduled(fixedDelay = 300000)
    public void synchronizeWithIaas() {
        iaasApiService.loadDataFromIaas();
    }
}
