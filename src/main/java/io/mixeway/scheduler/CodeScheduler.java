package io.mixeway.scheduler;

import io.mixeway.scanmanager.service.code.CodeScanService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@Component
@Log4j2
@RequiredArgsConstructor
public class CodeScheduler {
	private final CodeScanService codeScanService;

	
	@Transactional
	@Scheduled(cron="0 10 7,23 * * ?")
	//@Scheduled(initialDelay=0,fixedDelay = 1500000)
	public void getReportForAllGroups() {
		//codeScanService.schedulerReportSynchro();
	}
	@Transactional
	@Scheduled(cron="#{@getCodeCronExpression}" )
	public void runScheduledScans() {
		//codeScanService.schedulerRunAutoScans();
	}
	@Scheduled(fixedDelay = 60000, initialDelay = 10000)
	public void getVulns() {
		codeScanService.getResultsForRunningScan();
	}

	@Scheduled(fixedDelay = 60000)
	public void checkAndRunFromQueue() throws CertificateException, IOException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
		codeScanService.runFromQueue();
	}

}
