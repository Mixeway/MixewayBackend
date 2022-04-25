package io.mixeway.scheduler;


import io.mixeway.scanmanager.service.webapp.WebAppScanService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional
public class WebAppScheduler {
	private WebAppScanService webAppScanService;

    WebAppScheduler(WebAppScanService webAppScanService){
		this.webAppScanService = webAppScanService;
	}


	@Scheduled(fixedRate = 3000)
	public void checkAndDownload() throws Exception {
		webAppScanService.scheduledCheckAndDownloadResults();
	}


	@Scheduled(fixedRate = 30000)
	public void runScanFromQueue() throws Exception {
		webAppScanService.scheduledRunWebAppScanFromQueue();
	}

	/**
	 * Run WebApp Scheduled scan at defined rate
	 */
	@Scheduled(cron="#{@getWebAppCronExpresion}" )
	public void startAutomaticWebAppScans(){
		webAppScanService.scheduledRunWebAppScan(0);
	}

	/**
	 * Run priority queue every wednesday 23:30
	 */
	@Scheduled(cron="0 25 23 ? * WED" )
	public void startPriorityQueue(){
		webAppScanService.scheduledRunWebAppScan(1);
	}

}
