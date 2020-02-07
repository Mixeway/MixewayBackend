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
import java.util.List;
import java.util.Optional;

import javax.transaction.Transactional;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.codescan.service.CodeScanClient;
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
	private CodeGroupRepository codeGroupRepository;
	private CodeVulnRepository codeVulnRepository;
	private CodeProjectRepository codeProjectRepository;
	private ScannerRepository scannerRepository;
	private ScannerTypeRepository scannerTypeRepository;
	private FortifySingleAppRepository fortifySingleAppRepository;
	private ProjectRepository projectRepository;
	private List<CodeScanClient> codeScanClients;

	@Autowired
	CodeScheduler(CodeGroupRepository codeGroupRepository, CodeVulnRepository codeVulnRepository, CodeProjectRepository codeProjectRepository,
				  ScannerRepository scannerRepository, ScannerTypeRepository scannerTypeRepository, FortifySingleAppRepository fortifySingleAppRepository,
				  ProjectRepository projectRepository, List<CodeScanClient> codeScanClients){
		this.codeProjectRepository = codeProjectRepository;
		this.codeGroupRepository = codeGroupRepository;
		this.codeVulnRepository = codeVulnRepository;
		this.fortifySingleAppRepository = fortifySingleAppRepository;
		this.projectRepository = projectRepository;
		this.scannerRepository = scannerRepository;
		this.codeScanClients = codeScanClients;
		this.scannerTypeRepository = scannerTypeRepository;
	}
	
	
	//Pobranie wyników z SSC
	@Transactional
	@Scheduled(fixedRate = 3000000)
	//@Scheduled(fixedDelay = 30000)
	public void getReportForAllGroups() throws JSONException, ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		List<CodeGroup> groups = codeGroupRepository.findAll();
		Optional<Scanner> sastScanner = scannerRepository.findByScannerTypeIn(scannerTypeRepository.getCodeScanners()).stream().findFirst();
		if (sastScanner.isPresent() && sastScanner.get().getStatus()) {
			for (CodeGroup group : groups) {
				List<CodeVuln> tmpVulns = deleteOldVulns(group);
				if (group.getVersionIdAll() > 0) {
					for(CodeScanClient codeScanClient : codeScanClients){
						if (codeScanClient.canProcessRequest(sastScanner.get())){
							codeScanClient.loadVulnerabilities(sastScanner.get(),group,null,false,null,tmpVulns);
						}
					}
				}

			}
		}
		log.info("SAST Offline synchronization completed");
	}
	//Uruchomienie skanow dla grup
	@Transactional
	@Scheduled(cron="#{@getCodeCronExpression}" )
	public void runScheduledScans() throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, JSONException, ParseException {
		log.info("Starting Fortify Scheduled Scans");
		//List<CodeGroup> groups = codeGroupRepository.findByAuto(true);
		List<Project> projects = projectRepository.findByAutoCodeScan(true);
		Optional<Scanner> sastScanner = scannerRepository.findByScannerTypeIn(scannerTypeRepository.getCodeScanners()).stream().findFirst();
		if ( sastScanner.isPresent() &&  sastScanner.get().getStatus()) {
			for (Project p : projects){
				for (CodeGroup cg : p.getCodes()){
					if (!cg.getRepoPassword().equals("") && cg.getRepoPassword() != null){
						for(CodeScanClient codeScanClient : codeScanClients){
							if (codeScanClient.canProcessRequest(sastScanner.get())){
								codeScanClient.runScan(cg,null);
							}
						}
					}
				}
			}
		}
	}
	@Scheduled(fixedDelay = 30000)
	public void getVulns() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
		Optional<Scanner> sastScanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY)).stream().findFirst();
		if (sastScanner.isPresent()) {
			for (FortifySingleApp app : fortifySingleAppRepository.findByFinishedAndDownloaded(true, false)) {
				List<CodeVuln> codeVulns = codeVulns = deleteVulnsForProject(app.getCodeProject());
				for (CodeScanClient codeScanClient : codeScanClients) {
					if (codeScanClient.canProcessRequest(sastScanner.get()) && codeScanClient.isScanDone(app.getCodeGroup())) {
						codeScanClient.loadVulnerabilities(sastScanner.get(), app.getCodeGroup(), null, true, app.getCodeProject(), codeVulns);
						log.info("Vulerabilities for codescan for {} with scope of {} loaded - single app", app.getCodeGroup().getName(), app.getCodeProject().getName());
						app.setDownloaded(true);
						fortifySingleAppRepository.save(app);
						app.getCodeGroup().setRunning(false);
						app.getCodeGroup().setRequestid(null);
						app.getCodeGroup().setScanid(null);
						app.getCodeGroup().setScope(null);
						codeGroupRepository.save(app.getCodeGroup());
					}
				}
			}
			List<CodeGroup> codeGroups = codeGroupRepository.findByRunning(true);
			for (CodeGroup codeGroup : codeGroups) {
				for (CodeScanClient codeScanClient : codeScanClients) {
					if (codeScanClient.canProcessRequest(sastScanner.get()) && codeScanClient.isScanDone(codeGroup)) {
						deleteOldVulns(codeGroup);
						codeScanClient.loadVulnerabilities(sastScanner.get(), codeGroup, null, false, null, null);
						codeGroup.setRunning(false);
						codeGroup.setRequestid(null);
						codeGroup.setScanid(null);
						codeGroup.setScope(null);
						codeGroupRepository.save(codeGroup);
					}
				}
			}
		}
	}

	@Transactional
	@Scheduled(fixedDelay = 60000)
	public void checkAndRunFromQueue() throws CertificateException, IOException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
		Optional<Scanner> fortify = scannerRepository.findByScannerTypeIn(scannerTypeRepository.getCodeScanners()).stream().findFirst();
		if (fortify.isPresent() && fortify.get().getStatus()) {
			try {
				for (CodeProject cp : codeProjectRepository.findByInQueue(true)) {
					if (codeGroupRepository.countByRunning(true) == 0) {
						for (CodeScanClient codeScanClient : codeScanClients) {
							if (codeScanClient.canProcessRequest(cp.getCodeGroup())) {
								log.info("Ready to scan [scope {}] {}, taking it from the queue", cp.getName(), cp.getCodeGroup().getName());
								cp.setInQueue(false);
								codeProjectRepository.saveAndFlush(cp);
								codeScanClient.runScan(cp.getCodeGroup(), cp);
							}
						}
					}
				}
				for (CodeGroup cg : codeGroupRepository.findByInQueue(true)) {
					if (codeGroupRepository.countByRunning(true) == 0) {
						for (CodeScanClient codeScanClient : codeScanClients) {
							if (codeScanClient.canProcessRequest(cg)) {
								log.info("Ready to scan [scope ALL] {}, taking it from the queue", cg.getName());
								cg.setInQueue(false);
								codeGroupRepository.saveAndFlush(cg);
								codeScanClient.runScan(cg, null);
							}
						}
					}
				}

			} catch (IndexOutOfBoundsException ex) {
				log.debug("Fortify configuration missing");
			} catch (HttpClientErrorException ex) {
				log.warn("HttpClientErrorException with code [{}] during cloud scan job synchro ", ex.getStatusCode().toString());
			} catch (ParseException | JSONException e) {
				log.warn("Exception came up during running scan {}", e.getLocalizedMessage());
			}
		}
	}
	

	private List<CodeVuln> deleteOldVulns(CodeGroup group) {
		List<CodeVuln> tmpVulns = new ArrayList<>();
		if (group.getHasProjects()) {
			for (CodeProject cp : group.getProjects()) {
				tmpVulns.addAll(codeVulnRepository.findByCodeProject(cp));
				codeVulnRepository.deleteVulnsForCodeProject(cp);
			}
		} else{
			tmpVulns.addAll(codeVulnRepository.findByCodeGroup(group));
			codeVulnRepository.deleteVulnsForCodeGroup(group);
		}
		return tmpVulns;
	}
	private List<CodeVuln> deleteVulnsForProject(CodeProject codeProject){
		List<CodeVuln> codeVulns = codeVulnRepository.findByCodeProject(codeProject);
		codeVulnRepository.deleteVulnsForCodeProject(codeProject);
		return codeVulns;
	}

}
