package io.mixeway.plugins.infrastructurescan.scheduler;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

import javax.transaction.Transactional;
import javax.xml.bind.JAXBException;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.NessusScan;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.NessusScanRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.plugins.infrastructurescan.service.NetworkScanClient;
import io.mixeway.pojo.WebAppHelper;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
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
	@Autowired
	NetworkScanScheduler(NessusScanRepository nessusScanRepository, NetworkScanService networkScanService,
						 ScannerTypeRepository scannerTypeRepository, InterfaceRepository interfaceRepository,
						 WebAppHelper webAppHelper, List<NetworkScanClient> networkScanClients){
		this.scannerTypeRepository = scannerTypeRepository;
		this.interfaceRepository = interfaceRepository;
		this.nessusScanRepository = nessusScanRepository;
		this.webAppHelper = webAppHelper;
		this.networkScanClients = networkScanClients;
		this.networkScanService = networkScanService;
	}

	private static final Logger log = LoggerFactory.getLogger(NetworkScanScheduler.class);

	//Every 5min
	@Scheduled(initialDelay=0,fixedDelay = 3000)
	public void checkScanStatus() throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, JAXBException {
		List<NessusScan> nsl = nessusScanRepository.findByRunning(true);
		try {
			for (NessusScan ns : nsl) {
				if (ns.getNessus().getStatus()) {
					for (NetworkScanClient networkScanClient :networkScanClients) {
						if (networkScanClient.canProcessRequest(ns) && networkScanClient.isScanDone(ns)) {
							networkScanClient.loadVulnerabilities(ns);
							ns.setRunning(false);
							nessusScanRepository.save(ns);
							log.info("Loaded result for {} scan of {}",ns.getNessus().getScannerType().getName(), ns.getProject().getName());
						}
					}
					//For nessus create webapp linking
					if (ns.getNessus().getScannerType().equals(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NESSUS))) {
						if (ns.getProject().getWebAppAutoDiscover() != null && ns.getProject().getWebAppAutoDiscover())
							webAppHelper.discoverWebAppFromInfrastructureVulns(ns.getProject());
					}
					if (ns.getNessus().getRfwUrl() != null) {
						networkScanService.deleteRulsFromRfw(ns);
						log.info("RFW for scan {} is cleared - dropped traffic", ns.getProject().getName());
					}
				}
			}
		} catch (Exception ce){
			log.debug("Connection refused for one of scanners");
		}
	}
	//Every 12h
	@Scheduled(cron="0 0 10,21 * * *" )
	public void runScheduledTest() throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		log.info("Starting Scheduled task for automatic test");
		List<NessusScan> scans = nessusScanRepository.findByIsAutomatic(true);

		for (NessusScan ns : scans) {
			try {
				if (ns.getNessus().getStatus()) {
					for (NetworkScanClient networkScanClient :networkScanClients) {
						if (networkScanClient.canProcessRequest(ns) ) {
							networkScanClient.runScan(ns);
							ns.setRunning(false);
							nessusScanRepository.save(ns);
							log.info("{} Starting automatic scan for {}",ns.getNessus().getScannerType().getName(), ns.getProject().getName());
						}
					}
				}
			} catch (ResourceAccessException rae) {
				log.error("Scanner not avaliable - {}",rae.getLocalizedMessage());
			} catch (NullPointerException ex){
				log.error("Something wrong came up with scan for {}", ns.getProject().getName());
			} catch (HttpServerErrorException ex){
				log.error("HTTP Error during scan creation for {}", ns.getProject().getName());
			} catch (JAXBException e) {
				e.printStackTrace();
			}
		}

	}

}
