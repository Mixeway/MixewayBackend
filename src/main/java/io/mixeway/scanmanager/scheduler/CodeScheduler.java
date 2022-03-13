package io.mixeway.scanmanager.scheduler;

import io.mixeway.scanmanager.service.code.CodeScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;

@Component
@Transactional
@RequiredArgsConstructor
public class CodeScheduler {

	private final CodeScanService codeScanService;

	/**
	 * Get Vulnerabilities for running scan
	 */
	@Scheduled(fixedDelay = 30000)
	public void getVulns() {
		codeScanService.getResultsForRunningScan();
	}

	/**
	 * Start SAST scan taken form queue
	 */
	@Transactional
	@Scheduled(fixedDelay = 60000)
	public void checkAndRunFromQueue() {
		codeScanService.runFromQueue();
	}

}
