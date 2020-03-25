package io.mixeway.plugins.webappscan.scheduler;


import io.mixeway.plugins.webappscan.service.WebAppScanService;
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

	@Scheduled(cron="#{@getWebAppCronExpresion}" )
	public void startAutomaticWebAppScans(){
		webAppScanService.scheduledRunWebAppScan();
	}

}
