package io.mixeway.scanmanager.integrations.openvas.apiclient;

import com.google.gson.Gson;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.intf.InterfaceOperations;
import io.mixeway.domain.service.projectvulnerability.DeleteProjectVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.openvas.model.RestRequestBody;
import io.mixeway.scanmanager.integrations.openvas.model.User;
import io.mixeway.scanmanager.service.SecurityScanner;
import io.mixeway.scanmanager.service.network.NetworkScanClient;
import io.mixeway.utils.ScanHelper;
import io.mixeway.utils.ScannerModel;
import io.mixeway.utils.SecureRestTemplate;
import io.mixeway.utils.VaultHelper;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import javax.ws.rs.core.MediaType;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ProtocolException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;


@Component
public class OpenVasApiClient implements NetworkScanClient, SecurityScanner {
	@Value("${server.ssl.key-store}")
	private String keyStorePath;
	@Value("${server.ssl.key-store-password}")
	private String keyStorePassword;
	@Value("${server.ssl.trust-store}")
	private String trustStorePath;
	@Value("${server.ssl.trust-store-password}")
	private String trustStorePassword;
	private final static Logger log = LoggerFactory.getLogger(OpenVasApiClient.class);
	private DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	private final VaultHelper vaultHelper;
	private final ScanHelper scanHelper;
	private final ScannerRepository nessusRepository;
	private final InfraScanRepository infraScanRepository;
	private final InterfaceRepository interfaceRepository;
	private final AssetRepository assetRepository;
	private final SecureRestTemplate secureRestTemplate;
	private final ScannerRepository scannerRepository;
	private final ScannerTypeRepository scannerTypeRepository;
	private final ProxiesRepository proxiesRepository;
	private final RoutingDomainRepository routingDomainRepository;
	private final VulnTemplate vulnTemplate;
	private final InterfaceOperations interfaceOperations;
	private final DeleteProjectVulnerabilityService deleteProjectVulnerabilityService;
	OpenVasApiClient(VaultHelper vaultHelper, ScannerRepository nessusRepository, InfraScanRepository infraScanRepository, InterfaceRepository interfaceRepository,
					 AssetRepository assetRepository, ScanHelper scanHelper, InterfaceOperations interfaceOperations,
					 SecureRestTemplate secureRestTemplate, ScannerRepository scannerRepository,
					 ScannerTypeRepository scannerTypeRepository, ProxiesRepository proxiesRepository, RoutingDomainRepository routingDomainRepository,
					 VulnTemplate vulnTemplate, DeleteProjectVulnerabilityService deleteProjectVulnerabilityService){
		this.vaultHelper = vaultHelper;
		this.interfaceOperations = interfaceOperations;
		this.scanHelper = scanHelper;
		this.nessusRepository = nessusRepository;
		this.scannerRepository = scannerRepository;
		this.scannerTypeRepository = scannerTypeRepository;
		this.proxiesRepository = proxiesRepository;
		this.routingDomainRepository = routingDomainRepository;
		this.infraScanRepository = infraScanRepository;
		this.interfaceRepository = interfaceRepository;
		this.secureRestTemplate = secureRestTemplate;
		this.assetRepository = assetRepository;
		this.vulnTemplate = vulnTemplate;
		this.deleteProjectVulnerabilityService = deleteProjectVulnerabilityService;
	}


	@Override
	public boolean runScan(InfraScan ns) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		if (ns.getIsAutomatic()) {
			return runAutomaticScan(ns);
		}
		else if (ns.getTaskId() == null) {
			runScanManual(ns);
		}
		else {
			return runOnceManualScan(ns);
		}
		return false;
	}

	@Override
	public void runScanManual(InfraScan infraScan) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, IOException {
		InfraScan base = infraScan;
		try {
			RestRequestBody rrb = bodyPrepare(infraScan);
			rrb.setParams(prepareCreateTarget(infraScan));

			infraScan = createNewTarget(infraScan, rrb);
			infraScan = createNewTask(infraScan, rrb);
			infraScanRepository.save(infraScan);
			runScan(infraScan);
		} catch (NullPointerException npe){
			log.debug("Nullpointer thrown during runScanManual for {}", base.getProject().getName());
		}
	}

	@Override
	public boolean isScanDone(InfraScan infraScan) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyStoreException, KeyManagementException {
		try {
			RestRequestBody rrb = bodyPrepare(infraScan);
			HashMap<String, String> params = new HashMap<>();
			params.put(Constants.TASK_ID, infraScan.getTaskId());
			rrb.setParams(params);
			RestTemplate restTemplate = secureRestTemplate.noVerificationClientWithCert(infraScan.getNessus());
			HttpHeaders headers = new HttpHeaders();
			headers.set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
			HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(rrb),headers);
			ResponseEntity<String> response = restTemplate.exchange(infraScan.getNessus().getApiUrl() + "/checktask", HttpMethod.POST, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				String statusStr = new JSONObject(response.getBody()).getString(Constants.STATUS);
				boolean status = statusStr.equals(Constants.STATUS_DONE) || statusStr.equals(Constants.STATUS_STOPPED);
				boolean shouldStop = !statusStr.equals(Constants.STATUS_DONE) && !statusStr.equals(Constants.STATUS_RUNNING)
						&& !statusStr.equals(Constants.STATUS_REQUESTED)
						&& !statusStr.equals(Constants.STATUS_STOPPED) && !statusStr.equals(Constants.STATUS_QUEUEDGVM);
				log.debug("Status of {} is {}, boolean status: {}, shouldClear: {}", infraScan.getProject().getName(), statusStr, status, shouldStop);
				if (shouldStop){
					log.info("[OpenVas] Status of {} is {}, boolean status: {}, shouldClear: {}", infraScan.getProject().getName(), statusStr, status, shouldStop);
					infraScan.setRunning(false);
					infraScan.setTaskId(null);
					infraScanRepository.save(infraScan);
					interfaceRepository.disableScanRunningOnInterfaces(scanHelper.prepareTargetsForScan(infraScan,false));
				}
				if (new JSONObject(response.getBody()).getString(Constants.STATUS).equals(Constants.STATUS_DONE))
					log.debug("Checking status for task {} status is: {}", infraScan.getTaskId(),new JSONObject(response.getBody()).getString(Constants.STATUS));
				return status;
			}
		} catch (HttpClientErrorException e) {
			infraScan.setRunning(true);
			log.error("CheckStatus HTTP exception {} for {}", e.getRawStatusCode(), infraScan.getProject().getName());
		} catch (HttpServerErrorException e) {
			log.warn("Exception during checkStatus httpCode: {}",e.getStatusCode().toString());
		} catch (ResourceAccessException rae){
			log.debug("Exception during checkStatus httpCode: {}",rae.getLocalizedMessage());
		}

		return false;
	}

	@Override
	public void loadVulnerabilities(InfraScan infraScan) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		try {
			RestRequestBody rrb = bodyPrepare(infraScan);
			HashMap<String, String> params = new HashMap<>();
			params.put(Constants.REPORT_ID, infraScan.getReportId());
			rrb.setParams(params);
			RestTemplate restTemplate = secureRestTemplate.noVerificationClientWithCert(infraScan.getNessus());
			HttpHeaders headers = new HttpHeaders();
			headers.set("Content-Type", "application/json");
			HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(rrb),headers);
			ResponseEntity<String> response = restTemplate.exchange(infraScan.getNessus().getApiUrl() + "/getreport", HttpMethod.POST, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				setVulnerabilities(infraScan, response.getBody());
				//vulnTemplate.projectVulnerabilityRepository.deleteByStatusAndProject(vulnTemplate.STATUS_REMOVED, infraScan.getProject());
				deleteProjectVulnerabilityService.deleteProjectVulnerabilityWithStatus(infraScan.getProject(), vulnTemplate.STATUS_REMOVED, vulnTemplate.SOURCE_NETWORK);
				infraScan.setRunning(false);
				infraScan.setTaskId(null);
				infraScanRepository.save(infraScan);
				interfaceRepository.disableScanRunningOnInterfaces(scanHelper.prepareTargetsForScan(infraScan,false));
			}
		} catch (HttpClientErrorException ex) {
			infraScan.setRunning(false);
			infraScan.setTaskId(null);
			infraScanRepository.save(infraScan);
			log.error("GetReport HTTP exception {} for {}, stopping", ex.getRawStatusCode(), infraScan.getProject().getName());
		} catch (HttpServerErrorException e) {
			log.warn("Exception during getReport httpCode: {}",e.getStatusCode().toString());
			if (e.getStatusCode().equals(HttpStatus.INTERNAL_SERVER_ERROR)){
				infraScan.setRunning(false);
				infraScan.setTaskId(null);
				infraScanRepository.save(infraScan);
			}
		}
	}

	ResponseEntity<String> createRequest(String url, HttpHeaders httpHeaders, String body, HttpMethod method, Scanner scanner) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException{
		RestTemplate restTemplate = secureRestTemplate.noVerificationClientWithCert(scanner);
		if (httpHeaders == null)
			httpHeaders = new HttpHeaders();
		httpHeaders.set("Content-Type", "application/json");
		HttpEntity<String> entity = new HttpEntity<>(body,httpHeaders);
		return restTemplate.exchange(url, method, entity, String.class);
	}
	@Override
	public boolean initialize(Scanner nessus) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		ResponseEntity<String> response;
		try {
			String userString = new JSONObject(createUser(nessus.getUsername(), vaultHelper.getPassword(nessus.getPassword()))).toString();
			response = createRequest(nessus.getApiUrl() + "/initialize",null,userString,HttpMethod.POST, nessus);

			if (response.getStatusCode() == HttpStatus.OK) {
				updateScannerInfo(nessus, response.getBody());
				nessus.setStatus(true);
				nessusRepository.save(nessus);
				return true;
			}
			else {
				log.error("Initialization of scanner {} failed return code is: {}",nessus.getApiUrl(),response.getStatusCode().toString());
				return false;
			}
		} catch (ProtocolException e) {
			log.error("Exception occured during initialization of scanner: '{}'",e.getMessage());
		}
		return false;
	}

	@Override
	public boolean canProcessRequest(InfraScan infraScan) {
		return infraScan.getNessus().getScannerType().getName().equals(Constants.SCANNER_TYPE_OPENVAS);
	}

	private Boolean runOnceManualScan(InfraScan ns) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		RestRequestBody rrb = bodyPrepare(ns);
		HashMap<String, String> params = new HashMap<>();
		params.put(Constants.TASK_ID, ns.getTaskId());
		rrb.setParams(params);
		RestTemplate restTemplate = secureRestTemplate.noVerificationClientWithCert(ns.getNessus());
		HttpHeaders headers = new HttpHeaders();
		headers.set("Content-Type", "application/json");
		HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(rrb),headers);
		ResponseEntity<String> response = restTemplate.exchange(ns.getNessus().getApiUrl() + "/starttask", HttpMethod.POST, entity, String.class);
		if (response.getStatusCode() == HttpStatus.OK) {
			ns.setReportId(new JSONObject(Objects.requireNonNull(response.getBody())).getString(Constants.REPORT_ID));
			ns.setRunning(true);
			infraScanRepository.save(ns);
			return true;
		}
		else
			return false;
	}

	void setVulnerabilities(InfraScan ns, String body) throws JSONException  {
		List<ProjectVulnerability> oldVulns = getProjectVulnerabilititiesByScan(ns);
		List<ProjectVulnerability> vulnsToPersist = new ArrayList<>();
		List<Interface> scannerInterfaces = new ArrayList<>();
		// Set All old vulnerabilities status of removed
		if (oldVulns.size() > 0) {
			vulnTemplate.projectVulnerabilityRepository.updateVulnState(oldVulns.stream().map(ProjectVulnerability::getId).collect(Collectors.toList()),
					vulnTemplate.STATUS_REMOVED.getId());
			oldVulns.forEach(o -> o.setStatus(vulnTemplate.STATUS_REMOVED));
		}

		List<Asset> assetsActive = assetRepository.findByProject(ns.getProject());
		JSONObject vuln = new JSONObject(body);
		JSONArray vulns = vuln.getJSONArray(Constants.IF_VULNS);
		JSONObject v;
		Interface intfActive;
		log.info("[OpenVas] loading {} vulns for {}", vulns.length(),ns.getProject().getName());
		for (int i = 0; i < vulns.length(); i++) {
			v = vulns.getJSONObject(i);
			intfActive = loadInterface(ns,assetsActive,v.getString(Constants.IF_VULN_HOST) );
			if ( intfActive != null && intfActive.getSubnetId() == null && !intfActive.getAsset().getOrigin().equals("manual")) {
				assetsActive.add(intfActive.getAsset());
			}
			if (intfActive != null) {
				Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerability(v.getString(Constants.IF_VULN_NAME));
				ProjectVulnerability projectVulnerability = new ProjectVulnerability(intfActive,null,vulnerability,v.getString(Constants.IF_VULN_DESC),null
						,v.getString(Constants.IF_VULN_THREAT),v.getString(Constants.IF_VULN_PORT),null,null,vulnTemplate.SOURCE_NETWORK, null,null);
				//projectVulnerability.updateStatusAndGrade(oldVulns, vulnTemplate);
				vulnsToPersist.add(projectVulnerability);
				scannerInterfaces.add(intfActive);

				//vulnTemplate.vulnerabilityPersist(oldVulns,projectVulnerability);
				//vulnTemplate.projectVulnerabilityRepository.save(projectVulnerability);
			} else  {
				log.error("Report contains ip {} which is not found in assets for project {}",v.getString(Constants.IF_VULN_HOST), ns.getProject().getName());
			}

		}
		log.info("[OpenVAS] starting to persist vulns for {}", ns.getProject().getName());
		vulnTemplate.vulnerabilityPersistList(oldVulns, vulnsToPersist);
		scannerInterfaces.forEach(f -> f.setScanRunning(false));
		log.info("[OpenVas] finished loading vulns for {}", ns.getProject().getName());
	}

	// TODO: wczytanie interfejsow dla assetu i stremami wyszukanie
	private Interface loadInterface(InfraScan ns, List<Asset> assets, String string) {
		try {
			List<Interface> intf = interfaceRepository.getInterfaceForIPandAssets(string.trim(), assets);

			Optional<Interface> intefaceMatchingPatter = intf.stream()
					.filter(Interface::getActive)
					.findFirst();
			if ( intefaceMatchingPatter.isPresent())
				return intefaceMatchingPatter.get();
			else if (intf.size() > 0){
				return intf.get(0);
			} else {
				return createInterface(ns,string,assets.size());
			}
		} catch (InvalidDataAccessResourceUsageException e) {
			log.error("psql exception in {} - {}",string,assets.size());
		}
		return null;
	}
	public Interface createInterface (InfraScan ns, String ip, int size) {
		Interface intf = new Interface();
		Asset a = new Asset();
		log.debug("Adding unknown resource... {} - {}", ip, size);
		a.setName("Unknown Resource");
		a.setProject(ns.getProject());
		a.setOrigin("ServiceDiscovery");
		a.setActive(true);
		a.setRoutingDomain(ns.getProject().getAssets().iterator().next().getRoutingDomain());
		assetRepository.save(a);

		return interfaceOperations.createAndReturnInterfaceForAsset(a,ip);
	}

	private List<ProjectVulnerability> getProjectVulnerabilititiesByScan(InfraScan ns) {
		List<Interface> intfs = null;
		List<ProjectVulnerability> tmpVulns = new ArrayList<>();
		Long deleted = (long)0;
		if (ns.getIsAutomatic() && ns.getPublicip())
			intfs = interfaceRepository.findByAssetInAndFloatingipNotNull(new ArrayList<>(ns.getProject().getAssets()));
		else if (ns.getIsAutomatic() && !ns.getPublicip())
			intfs = interfaceRepository.findByAssetInAndRoutingDomain(new ArrayList<>(ns.getProject().getAssets()), ns.getNessus().getRoutingDomain());
		else if (!ns.getIsAutomatic() ) {
			intfs = new ArrayList<>(ns.getInterfaces());
		}
		assert intfs != null;
		return getInfrastructureVulns(ns, intfs, tmpVulns, deleted, interfaceRepository, log, vulnTemplate.projectVulnerabilityRepository);
	}

	private static List<ProjectVulnerability> getInfrastructureVulns(InfraScan ns, List<Interface> intfs, List<ProjectVulnerability> tmpVulns, Long deleted, InterfaceRepository interfaceRepository, Logger log, ProjectVulnerabilityRepository projectVulnerabilityRepository) {
		assert intfs != null;
		for( Interface i : intfs) {
			tmpVulns.addAll(projectVulnerabilityRepository.findByAnInterface(i));
		}
		return tmpVulns;
	}

	private Boolean runAutomaticScan(InfraScan ns) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {

		if (ns.getIsAutomatic()) {
			RestRequestBody rrb = bodyPrepare(ns);
			rrb.setParams(prepareCreateTarget(ns));
			log.debug("Creating new targets for automatic scan");
			try {
				ns = createNewTarget(ns,rrb);
				log.debug("Creating task configuration for automatic scan");
				ns = createNewTask(ns,rrb);
			} catch (HttpServerErrorException  | NullPointerException ex) {
				assert ns != null;
				log.error("RunAutomaticScan server HTTP exception {} for {}", ex.getLocalizedMessage(), ns.getProject().getName());
			}
			infraScanRepository.save(ns);
			log.debug("Starting running task");
			return runAutoScan(ns);

		}

		return false;
	}

	private Boolean runAutoScan(InfraScan ns) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
		try {
			RestRequestBody rrb = bodyPrepare(ns);
			HashMap<String, String> params = new HashMap<>();
			params.put(Constants.TASK_ID, ns.getTaskId());
			rrb.setParams(params);
			RestTemplate restTemplate = secureRestTemplate.noVerificationClientWithCert(ns.getNessus());
			HttpHeaders headers = new HttpHeaders();
			headers.set("Content-Type", "application/json");
			HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(rrb),headers);
			ResponseEntity<String> response = restTemplate.exchange(ns.getNessus().getApiUrl() + "/starttask", HttpMethod.POST, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				ns.setReportId(new JSONObject(Objects.requireNonNull(response.getBody())).getString(Constants.REPORT_ID));
				ns.setRunning(true);
				infraScanRepository.save(ns);
				return true;
			}
			else
				return false;
		} catch (HttpClientErrorException | HttpServerErrorException ex) {
			log.error("RunAutoScan HTTP exception {} for {}", ex.getRawStatusCode(), ns.getProject().getName());
		}
		return false;

	}

	private InfraScan createNewTask(InfraScan ns, RestRequestBody rrb) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
		HashMap<String, String> params = new HashMap<>();
		params.put(Constants.CONFIG_ID, ns.getNessus().getConfigId());
		params.put(Constants.SCANNER_ID, ns.getNessus().getScannerid());
		params.put(Constants.TARGET_ID, ns.getTargetId());
		params.put(Constants.TARGET_NAME,ns.getProject().getName()+"-"+(ns.getIsAutomatic()? Constants.SCAN_MODE_AUTO : Constants.SCAN_MODE_MANUAL));
		rrb.setParams(params);
		RestTemplate restTemplate = secureRestTemplate.noVerificationClientWithCert(ns.getNessus());
		HttpHeaders headers = new HttpHeaders();
		headers.set("Content-Type", "application/json");
		HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(rrb),headers);
		ResponseEntity<String> response = restTemplate.exchange(ns.getNessus().getApiUrl() + "/createtask", HttpMethod.POST, entity, String.class);
		if (response.getStatusCode() == HttpStatus.OK) {
			ns.setTaskId(new JSONObject(Objects.requireNonNull(response.getBody())).getString(Constants.TASK_ID));
			log.debug("Task Creation success");
			return ns;
		}
		return ns;
	}
	private InfraScan createNewTarget(InfraScan ns, RestRequestBody rrb) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
		try {
			RestTemplate restTemplate = secureRestTemplate.noVerificationClientWithCert(ns.getNessus());
			HttpHeaders headers = new HttpHeaders();
			headers.set("Content-Type", "application/json");
			HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(rrb), headers);
			ResponseEntity<String> response = restTemplate.exchange(ns.getNessus().getApiUrl() + "/createtarget", HttpMethod.POST, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				ns.setTargetId(new JSONObject(Objects.requireNonNull(response.getBody())).getString(Constants.TARGET_ID));
				log.debug("Target creation success");
				return ns;
			}
			return ns;
		} catch (HttpClientErrorException hcee){
			log.error("Error occured during target creation for {} with code {}",ns.getProject().getName(),hcee.getLocalizedMessage() );
		}
		return null;
	}
	// Jeśli nessus.usePublic = true
	// ips = private + floating ips
	@Transactional
	HashMap<String, String> prepareCreateTarget(InfraScan ns) {
		HashMap<String,String> createTarget = new HashMap<>();
		createTarget.put(Constants.TARGET_NAME, ns.getProject().getName()+"-"+(ns.getIsAutomatic()? Constants.SCAN_MODE_AUTO : Constants.SCAN_MODE_MANUAL)+"-"+UUID.randomUUID());
		//createTarget.put(Constants.HOSTS, StringUtils.join(ips, ","));
		createTarget.put(Constants.HOSTS, StringUtils.join(scanHelper.prepareTargetsForScan(ns,true), ","));
		return createTarget;
	}
	public RestRequestBody bodyPrepare(InfraScan ns) {
		try {
			User u = new User();
			u.setUsername(ns.getNessus().getUsername());
			u.setPassword(vaultHelper.getPassword(ns.getNessus().getPassword()));
			RestRequestBody rrb = new RestRequestBody();
			rrb.setUser(u);
			return rrb;
		} catch (ResourceAccessException ex){
			log.error("Vault respourse is not accessible.");
			throw ex;
		}
	}


	private void updateScannerInfo(Scanner nessus, String body) throws JSONException {
		JSONObject jsonResponse = new JSONObject(body);
		nessus.setScannerid(jsonResponse.getString("scanner_id"));
		nessus.setConfigId(jsonResponse.getString("config_id"));
		nessusRepository.save(nessus);
		log.debug("Updated info for {} - scannerid and configid", nessus.getApiUrl());

	}




	private HashMap<String, String> createUser(String u, String p){
		HashMap<String, String> user = new HashMap<>();
		user.put("username", u);
		user.put("password", p);
		return user;
	}

	@Override
	public boolean canProcessRequest(Scanner scanner) {
		return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_OPENVAS) && scanner.getStatus();
	}

	@Override
	public boolean canProcessInitRequest(Scanner scanner) {
		return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_OPENVAS);
	}

	@Override
	public boolean canProcessRequest(RoutingDomain routingDomain) {
		List<Scanner> infraScanners = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase("OpenVAS"));
		for (Scanner scanner : infraScanners) {
			if (routingDomain != null && routingDomain.getName().startsWith(scanner.getRoutingDomain().getName())){
				return true;
			}
		}
		//List<Scanner> scanner = scannerRepository.findByScannerTypeAndRoutingDomain(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS), routingDomain);
		//return scanner.size() == 1 && scanner.get(0).getRoutingDomain().getId().equals(routingDomain.getId());
		return false;
	}

	@Override
	public Scanner getScannerFromClient(RoutingDomain routingDomain) {
		List<Scanner> scanner = scannerRepository.findByScannerTypeAndRoutingDomain(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS), routingDomain);
		return scanner.stream().findFirst().orElse(null);
	}

	@Override
	public String printInfo() {
		return "GVMD Scanner";
	}

	@Override
	public boolean canProcessRequest(ScannerType scannerType) {
		return scannerType.getName().equals(Constants.SCANNER_TYPE_OPENVAS);
	}

	@Override
	public Scanner saveScanner(ScannerModel scannerModel) throws Exception {
		ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
		Proxies proxy = null;
		if (scannerModel.getProxy() != 0)
			proxy = proxiesRepository.getOne(scannerModel.getProxy());
		if (scannerType.getName().equals(Constants.SCANNER_TYPE_OPENVAS) || scannerType.getName().equals(Constants.SCANNER_TYPE_NEXPOSE) ||
				scannerType.getName().equals(Constants.SCANNER_TYPE_OPENVAS_SOCKET)) {
			Scanner nessus = new Scanner();
			nessus.setUsername(scannerModel.getUsername());
			nessus = nessusOperations(scannerModel.getRoutingDomain(),nessus,proxy,scannerModel.getApiUrl(),scannerType);
			String uuidToken = UUID.randomUUID().toString();
			if (vaultHelper.savePassword(scannerModel.getPassword(), uuidToken)){
				nessus.setPassword(uuidToken);
			} else {
				nessus.setPassword(scannerModel.getPassword());
			}
			return scannerRepository.save(nessus);
		}
		return null;
	}
	private Scanner nessusOperations(Long domainId, Scanner nessus, Proxies proxy, String apiurl, ScannerType scannerType) throws Exception{
		if(domainId == 0)
			throw new Exception("Null domain");
		else
			nessus.setRoutingDomain(routingDomainRepository.getOne(domainId));
		nessus.setProxies(proxy);
		nessus.setStatus(false);
		nessus.setApiUrl(apiurl);
		nessus.setScannerType(scannerType);
		nessus.setUsePublic(false);
		scannerRepository.save(nessus);

		return nessus;
	}

}

