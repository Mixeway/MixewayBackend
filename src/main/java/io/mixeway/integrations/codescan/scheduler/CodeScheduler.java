package io.mixeway.integrations.codescan.scheduler;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;

import javax.transaction.Transactional;

import io.mixeway.integrations.codescan.service.CodeScanService;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@Transactional
public class CodeScheduler {
	private static final Logger log = LoggerFactory.getLogger(CodeScheduler.class);
	private final CodeScanService codeScanService;


	CodeScheduler(CodeScanService codeScanService){
		this.codeScanService = codeScanService;
	}
	
	
	@Transactional
	@Scheduled(cron="0 55 7,22 * * ?")
	//@Scheduled(initialDelay=0,fixedDelay = 1500000)
	public void getReportForAllGroups() throws JSONException, ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, URISyntaxException {
		codeScanService.schedulerReportSynchro();
	}
	@Transactional
	@Scheduled(cron="#{@getCodeCronExpression}" )
	public void runScheduledScans() throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, JSONException, ParseException {
		codeScanService.schedulerRunAutoScans();
	}
	@Scheduled(fixedDelay = 30000)
	public void getVulns() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException, URISyntaxException {
		codeScanService.getResultsForRunningScan();
	}

	@Transactional
	@Scheduled(fixedDelay = 60000)
	public void checkAndRunFromQueue() throws CertificateException, IOException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
		codeScanService.runFromQueue();
	}

}
