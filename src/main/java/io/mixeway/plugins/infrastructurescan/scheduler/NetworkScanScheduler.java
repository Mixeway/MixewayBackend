package io.mixeway.plugins.infrastructurescan.scheduler;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.sql.SQLException;
import java.util.List;

import javax.transaction.Transactional;
import javax.xml.bind.JAXBException;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.NessusScan;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.NessusScanRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.plugins.infrastructurescan.service.NetworkScanClient;
import io.mixeway.pojo.WebAppHelper;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.UnexpectedRollbackException;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;

import io.mixeway.plugins.infrastructurescan.service.NetworkScanService;

@Component
@Transactional
public class NetworkScanScheduler {
	private NessusScanRepository nessusScanRepository;
	private ScannerTypeRepository scannerTypeRepository;
	private InterfaceRepository interfaceRepository;
	private WebAppHelper webAppHelper;
	private final List<NetworkScanClient> networkScanClients;
	private final NetworkScanService networkScanService;
	private final ProjectRepository projectRepository;
	@Autowired
	NetworkScanScheduler(NessusScanRepository nessusScanRepository, NetworkScanService networkScanService,
						 ScannerTypeRepository scannerTypeRepository, ProjectRepository projectRepository,
						 WebAppHelper webAppHelper, List<NetworkScanClient> networkScanClients, InterfaceRepository interfaceRepository){
		this.scannerTypeRepository = scannerTypeRepository;
		this.nessusScanRepository = nessusScanRepository;
		this.interfaceRepository = interfaceRepository;
		this.webAppHelper = webAppHelper;
		this.projectRepository = projectRepository;
		this.networkScanClients = networkScanClients;
		this.networkScanService = networkScanService;
	}

	private static final Logger log = LoggerFactory.getLogger(NetworkScanScheduler.class);

	//Every 5min
	@Scheduled(initialDelay=0,fixedDelay = 30000)
	public void checkScanStatus(){
		try {
			List<NessusScan> nsl = nessusScanRepository.findTop4ByRunningOrderByIdAsc(true);
			for (NessusScan ns : nsl) {
				if (ns.getNessus().getStatus()) {
					for (NetworkScanClient networkScanClient :networkScanClients) {
						if (networkScanClient.canProcessRequest(ns) && networkScanClient.isScanDone(ns)) {
							networkScanClient.loadVulnerabilities(ns);
						}
					}
					//For nessus create webapp linking
					if (ns.getNessus().getScannerType().equals(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NESSUS))) {
						if (ns.getProject().getWebAppAutoDiscover() != null && ns.getProject().getWebAppAutoDiscover())
							webAppHelper.discoverWebAppFromInfrastructureVulns(ns.getProject());
					}

				}
			}
			//Change state of interface which was not loaded for some reason
			if (nessusScanRepository.findByRunning(true).size() == 0 ){
				interfaceRepository.updateStateForNotRunningScan();
			}
		} catch (UnexpectedRollbackException | JSONException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException | JAXBException| HttpClientErrorException ce ){
			log.warn("Exception during Network Scan synchro {}", ce.getLocalizedMessage());
		}
		log.info("Successfully loaded Network scan results");
	}
	//Every 12h
	@Scheduled(cron="#{@getNetworkCronExpresion}" )
	public void runScheduledTest() throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		log.info("Starting Scheduled task for automatic test");
		List<Project> autoInfraProjectList = projectRepository.findByAutoInfraScan(true);

		for (Project project : autoInfraProjectList){
			List<NessusScan> nessusScan = nessusScanRepository.findByProjectAndIsAutomatic(project,true);
			for (NessusScan ns : nessusScan) {
				try {
					if (ns.getNessus().getStatus()) {
						for (NetworkScanClient networkScanClient :networkScanClients) {
							if (networkScanClient.canProcessRequest(ns) ) {
								networkScanClient.runScan(ns);
								log.info("{} Starting automatic scan for {}",ns.getNessus().getScannerType().getName(), ns.getProject().getName());
							}
						}
					}
				} catch (ResourceAccessException | NullPointerException | HttpServerErrorException | JAXBException | HttpClientErrorException e) {
					log.error("Exception - {} came up during scan for {}",e.getLocalizedMessage(), ns.getProject().getName());
				}
			}
		}

	}

}

