package io.mixeway.integrations.infrastructurescan.scheduler;


import javax.transaction.Transactional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import io.mixeway.integrations.infrastructurescan.service.NetworkScanService;

import java.time.Duration;
import java.util.concurrent.*;

@Component
@Transactional
public class NetworkScanScheduler {
	private final NetworkScanService networkScanService;
	private static final Logger log = LoggerFactory.getLogger(NetworkScanScheduler.class);
	NetworkScanScheduler(NetworkScanService networkScanService){
		this.networkScanService = networkScanService;
	}

	@Scheduled(initialDelay=0,fixedDelay = 60000)
	public void checkScanStatus(){
		ExecutorService executor = Executors.newSingleThreadExecutor();
		Future<String> future = executor.submit((Callable) () -> {
			networkScanService.scheduledCheckStatusAndLoadVulns();
			return "OK";
		});
		try {
			future.get(3, TimeUnit.MINUTES);
		} catch (TimeoutException ex) {
			log.warn("[NetworkScanServiceScheduler] 3 minutes lmit exceeded for loading vulns... interrupting..");
		} catch (InterruptedException e) {
			log.warn("[NetworkScanServiceScheduler] Vuln loading interrupted");
		} catch (ExecutionException e) {
			log.warn("[NetworkScanServiceScheduler] ExecutionException during vuln loading..");
		}
		executor.shutdownNow();

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

