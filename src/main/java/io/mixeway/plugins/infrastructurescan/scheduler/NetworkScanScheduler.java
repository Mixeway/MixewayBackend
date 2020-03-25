package io.mixeway.plugins.infrastructurescan.scheduler;


import javax.transaction.Transactional;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import io.mixeway.plugins.infrastructurescan.service.NetworkScanService;

@Component
@Transactional
public class NetworkScanScheduler {
	private final NetworkScanService networkScanService;

	NetworkScanScheduler(NetworkScanService networkScanService){
		this.networkScanService = networkScanService;
	}

	@Scheduled(initialDelay=0,fixedDelay = 30000)
	public void checkScanStatus(){
		networkScanService.scheduledCheckStatusAndLoadVulns();
	}
	@Scheduled(cron="#{@getNetworkCronExpresion}" )
	public void runScheduledTest() {
		networkScanService.scheduledRunScans();

	}

}

