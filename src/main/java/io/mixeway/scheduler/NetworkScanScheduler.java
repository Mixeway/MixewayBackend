package io.mixeway.scheduler;


import io.mixeway.scanmanager.service.network.NetworkScanService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;

@Component
@Transactional
@Log4j2
@RequiredArgsConstructor
public class NetworkScanScheduler {
	private final NetworkScanService networkScanService;

	@Scheduled(initialDelay=0,fixedDelay = 60000)
	public void checkScanStatus(){
		networkScanService.scheduledCheckStatusAndLoadVulns();

	}
	@Scheduled(cron="#{@getNetworkCronExpresion}" )
	public void runScheduledTest() throws Exception {
		networkScanService.scheduledRunScans();

	}


	/**
	 * Method which verify if Network Scan is running (or some kind of error occured), if there is Interface.scanRunning with no nessusscan.running
	 * terminate running interfaces. Otherwise another scan cannot be started
	 */
	@Scheduled(initialDelay=0,fixedDelay = 300000)
	public void verifyInterfaceState(){
		networkScanService.verifyInteraceState();
	}

	/**
	 * Method which takes scans in queue and run them if it is possible
	 */
	@Scheduled(initialDelay=0,fixedDelay = 300000)
	public void runScansFromQueue() throws Exception {
		networkScanService.runScansFromQueue();
	}
}

