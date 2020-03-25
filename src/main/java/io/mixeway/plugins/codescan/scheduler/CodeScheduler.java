package io.mixeway.plugins.codescan.scheduler;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import javax.transaction.Transactional;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.codescan.service.CodeScanClient;
import io.mixeway.plugins.codescan.service.CodeScanService;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import org.springframework.web.client.HttpClientErrorException;

@Component
@Transactional
public class CodeScheduler {
	private static final Logger log = LoggerFactory.getLogger(CodeScheduler.class);
	private final CodeScanService codeScanService;


	CodeScheduler(CodeScanService codeScanService){
		this.codeScanService = codeScanService;
	}
	
	
	@Transactional
	@Scheduled(fixedRate = 3000000)
	public void getReportForAllGroups() throws JSONException, ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		codeScanService.schedulerReportSynchro();
	}
	@Transactional
	@Scheduled(cron="#{@getCodeCronExpression}" )
	public void runScheduledScans() throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, JSONException, ParseException {
		codeScanService.schedulerRunAutoScans();
	}
	@Scheduled(fixedDelay = 30000)
	public void getVulns() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
		codeScanService.getResultsForRunningScan();
	}

	@Transactional
	@Scheduled(fixedDelay = 60000)
	public void checkAndRunFromQueue() throws CertificateException, IOException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
		codeScanService.runFromQueue();
	}

}
