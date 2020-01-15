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
	public void getReportForAllGroups() throws JSONException, ParseException {
		List<CodeGroup> groups = codeGroupRepository.findAll();
		Optional<Scanner> fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY)).stream().findFirst();
		if (fortify.isPresent() && fortify.get().getStatus()) {
			for (CodeGroup group : groups) {
				List<CodeVuln> tmpVulns = deleteOldVulns(group);
				if (group.getVersionIdAll() > 0) {
					for(CodeScanClient codeScanClient : codeScanClients){
						if (codeScanClient.canProcessRequest(group)){
							codeScanClient.loadVulnerabilities(fortify.get(),group,null,false,null,tmpVulns);
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
	public void runScheduledScans() throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		log.info("Starting Fortify Scheduled Scans");
		//List<CodeGroup> groups = codeGroupRepository.findByAuto(true);
		List<Project> projects = projectRepository.findByAutoCodeScan(true);
		List<Scanner> fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY));
		if ( fortify.size() > 0 &&  fortify.get(0).getStatus()) {
			for (Project p : projects){
				for (CodeGroup cg : p.getCodes()){
					if (!cg.getRepoPassword().equals("") && cg.getRepoPassword() != null){
						for(CodeScanClient codeScanClient : codeScanClients){
							if (codeScanClient.canProcessRequest(cg)){
								codeScanClient.runScan(cg,null);
							}
						}
					}
				}
			}
		}
	}
	@Transactional
	@Scheduled(fixedDelay = 30000)
	public void getVulns() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
		Optional<Scanner> fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY)).stream().findFirst();
		if (fortify.isPresent()) {
			for (FortifySingleApp app : fortifySingleAppRepository.findByFinishedAndDownloaded(true, false)) {
				List<CodeVuln> codeVulns = codeVulns = deleteVulnsForProject(app.getCodeProject());
				for (CodeScanClient codeScanClient : codeScanClients) {
					if (codeScanClient.canProcessRequest(app.getCodeGroup()) && codeScanClient.isScanDone(app.getCodeGroup())) {
						codeScanClient.loadVulnerabilities(fortify.get(), app.getCodeGroup(), null, true, app.getCodeProject(), codeVulns);
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
					if (codeScanClient.canProcessRequest(codeGroup) && codeScanClient.isScanDone(codeGroup)) {
						deleteOldVulns(codeGroup);
						codeScanClient.loadVulnerabilities(fortify.get(), codeGroup, null, false, null, null);
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
	@Scheduled(fixedDelay = 120000)
	public void checkAndRunFromQueue() throws CertificateException, IOException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
		try {
			Scanner fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY))
					.stream()
					.findFirst()
					.orElse(null);
			for (CodeGroup cg : codeGroupRepository.findByInQueue(true)) {
				if (codeGroupRepository.countByRunning(true) == 0) {
					for(CodeScanClient codeScanClient : codeScanClients){
						if (codeScanClient.canProcessRequest(cg)){
							log.info("Ready to scan [scope ALL] {}, taking it from the queue", cg.getName());
							cg.setInQueue(false);
							codeGroupRepository.save(cg);
							codeScanClient.runScan(cg, null);
						}
					}
				}
			}
			for (CodeProject cp : codeProjectRepository.findByInQueue(true)){
				if (codeGroupRepository.countByRunning(true) == 0){
					for(CodeScanClient codeScanClient : codeScanClients){
						if (codeScanClient.canProcessRequest(cp.getCodeGroup())){
							log.info("Ready to scan [scope {}}] {}, taking it from the queue",cp.getName(), cp.getCodeGroup().getName());
							cp.setInQueue(false);
							codeProjectRepository.save(cp);
							codeScanClient.runScan(cp.getCodeGroup(), cp);
						}
					}
				}
			}
		} catch (IndexOutOfBoundsException ex){
			log.debug("Fortify configuration missing");
		} catch (HttpClientErrorException ex){
			log.warn("HttpClientErrorException with code [{}] during cloud scan job synchro ",ex.getStatusCode().toString());
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
