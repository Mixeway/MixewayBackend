package io.mixeway.integrations.infrastructurescan.plugin.openvas.apiclient;

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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.vulnerability.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.infrastructurescan.plugin.openvas.model.RestRequestBody;
import io.mixeway.integrations.infrastructurescan.plugin.openvas.model.User;
import io.mixeway.integrations.infrastructurescan.service.NetworkScanClient;
import io.mixeway.pojo.SecureRestTemplate;
import io.mixeway.pojo.SecurityScanner;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.model.ScannerModel;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import com.google.gson.Gson;


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
	private VaultHelper vaultHelper;
	private ScannerRepository nessusRepository;
	private NessusScanRepository nessusScanRepository;
	private InterfaceRepository interfaceRepository;
	private AssetRepository assetRepository;
	private SecureRestTemplate secureRestTemplate;
	private ScannerRepository scannerRepository;
	private ScannerTypeRepository scannerTypeRepository;
	private ProxiesRepository proxiesRepository;
	private RoutingDomainRepository routingDomainRepository;
	private VulnTemplate vulnTemplate;
	OpenVasApiClient(VaultHelper vaultHelper, ScannerRepository nessusRepository, NessusScanRepository nessusScanRepository, InterfaceRepository interfaceRepository,
					 AssetRepository assetRepository,
					 SecureRestTemplate secureRestTemplate, ScannerRepository scannerRepository,
					 ScannerTypeRepository scannerTypeRepository, ProxiesRepository proxiesRepository, RoutingDomainRepository routingDomainRepository,
					 VulnTemplate vulnTemplate){
		this.vaultHelper = vaultHelper;
		this.nessusRepository = nessusRepository;
		this.scannerRepository = scannerRepository;
		this.scannerTypeRepository = scannerTypeRepository;
		this.proxiesRepository = proxiesRepository;
		this.routingDomainRepository = routingDomainRepository;
		this.nessusScanRepository = nessusScanRepository;
		this.interfaceRepository = interfaceRepository;
		this.secureRestTemplate = secureRestTemplate;
		this.assetRepository = assetRepository;
		this.vulnTemplate = vulnTemplate;
	}


	@Override
	public boolean runScan(NessusScan ns) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		if (ns.getIsAutomatic())
			return runAutomaticScan(ns);
		else
			return runOnceManualScan(ns);
	}

	@Override
	public void runScanManual(NessusScan nessusScan) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, IOException {
		NessusScan base = nessusScan;
		try {
			RestRequestBody rrb = bodyPrepare(nessusScan);
			rrb.setParams(prepareCreateTarget(nessusScan));

			nessusScan = createNewTarget(nessusScan, rrb);
			nessusScan = createNewTask(nessusScan, rrb);
			nessusScanRepository.save(nessusScan);
			runScan(nessusScan);
		} catch (NullPointerException npe){
			log.debug("Nullpointer thrown during runScanManual for {}", base.getProject().getName());
		}
	}

	@Override
	public boolean isScanDone(NessusScan nessusScan) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyStoreException, KeyManagementException {
		try {
			RestRequestBody rrb = bodyPrepare(nessusScan);
			HashMap<String, String> params = new HashMap<>();
			params.put(Constants.TASK_ID, nessusScan.getTaskId());
			rrb.setParams(params);
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
			HttpHeaders headers = new HttpHeaders();
			headers.set("Content-Type", "application/json");
			HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(rrb),headers);
			ResponseEntity<String> response = restTemplate.exchange(nessusScan.getNessus().getApiUrl() + "/checktask", HttpMethod.POST, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				String statusStr = new JSONObject(response.getBody()).getString(Constants.STATUS);
				Boolean status = statusStr.equals(Constants.STATUS_DONE);
				nessusScan.setRunning(status);
				nessusScanRepository.save(nessusScan);
				if (new JSONObject(response.getBody()).getString(Constants.STATUS).equals(Constants.STATUS_DONE))
					log.debug("Checking status for task {} status is: {}", nessusScan.getTaskId(),new JSONObject(response.getBody()).getString(Constants.STATUS));
				return status;
			}
		} catch (HttpClientErrorException e) {
			log.error("CheckStatus HTTP exception {} for {}", e.getRawStatusCode(), nessusScan.getProject().getName());
		} catch (HttpServerErrorException e) {
			log.warn("Exception during checkStatus httpCode: {}",e.getStatusCode().toString());
		} catch (ResourceAccessException rae){
			log.debug("Exception during checkStatus httpCode: {}",rae.getLocalizedMessage());
		}

		return false;
	}

	@Override
	public void loadVulnerabilities(NessusScan nessusScan) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		try {
			RestRequestBody rrb = bodyPrepare(nessusScan);
			HashMap<String, String> params = new HashMap<>();
			params.put(Constants.REPORT_ID, nessusScan.getReportId());
			rrb.setParams(params);
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
			HttpHeaders headers = new HttpHeaders();
			headers.set("Content-Type", "application/json");
			HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(rrb),headers);
			ResponseEntity<String> response = restTemplate.exchange(nessusScan.getNessus().getApiUrl() + "/getreport", HttpMethod.POST, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				setVulnerabilities(nessusScan, response.getBody());
			}
			vulnTemplate.projectVulnerabilityRepository.deleteByStatus(vulnTemplate.STATUS_REMOVED);
			nessusScan.setRunning(false);
			nessusScanRepository.save(nessusScan);
		} catch (HttpClientErrorException ex) {
			log.error("GetReport HTTP exception {} for {}", ex.getRawStatusCode(), nessusScan.getProject().getName());
		} catch (HttpServerErrorException e) {
			log.warn("Exception during getReport httpCode: {}",e.getStatusCode().toString());
		}
	}

	ResponseEntity<String> createRequest(String url, HttpHeaders httpHeaders, String body, HttpMethod method) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException{
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
		if (httpHeaders == null)
			httpHeaders = new HttpHeaders();
		httpHeaders.set("Content-Type", "application/json");
		HttpEntity<String> entity = new HttpEntity<>(body,httpHeaders);
		return restTemplate.exchange(url, method, entity, String.class);
	}
	@Override
	public boolean initialize(io.mixeway.db.entity.Scanner nessus) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		ResponseEntity<String> response;
		try {
			String userString = new JSONObject(createUser(nessus.getUsername(), vaultHelper.getPassword(nessus.getPassword()))).toString();
			response = createRequest(nessus.getApiUrl() + "/initialize",null,userString,HttpMethod.POST);

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
	public boolean canProcessRequest(NessusScan nessusScan) {
		return nessusScan.getNessus().getScannerType().getName().equals(Constants.SCANNER_TYPE_OPENVAS);
	}

	private Boolean runOnceManualScan(NessusScan ns) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		RestRequestBody rrb = bodyPrepare(ns);
		HashMap<String, String> params = new HashMap<>();
		params.put(Constants.TASK_ID, ns.getTaskId());
		rrb.setParams(params);
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
		HttpHeaders headers = new HttpHeaders();
		headers.set("Content-Type", "application/json");
		HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(rrb),headers);
		ResponseEntity<String> response = restTemplate.exchange(ns.getNessus().getApiUrl() + "/starttask", HttpMethod.POST, entity, String.class);
		if (response.getStatusCode() == HttpStatus.OK) {
			ns.setReportId(new JSONObject(Objects.requireNonNull(response.getBody())).getString(Constants.REPORT_ID));
			ns.setRunning(true);
			nessusScanRepository.save(ns);
			return true;
		}
		else
			return false;
	}

	private void setVulnerabilities(NessusScan ns, String body) throws JSONException  {
		List<ProjectVulnerability> oldVulns = getProjectVulnerabilititiesByScan(ns);
		if (oldVulns.size() > 0)
			vulnTemplate.projectVulnerabilityRepository.updateVulnState(oldVulns.stream().map(ProjectVulnerability::getId).collect(Collectors.toList()),
					vulnTemplate.STATUS_REMOVED.getId());

		List<Asset> assetsActive = assetRepository.findByProject(ns.getProject());
		JSONObject vuln = new JSONObject(body);
		JSONArray vulns = vuln.getJSONArray(Constants.IF_VULNS);
		JSONObject v;
		Interface intfActive;
		log.info("OpenVas loading {} vulns for {}", vulns.length(),ns.getProject().getName());
		for (int i = 0; i < vulns.length(); i++) {
			v = vulns.getJSONObject(i);
			intfActive = loadInterface(ns,assetsActive,v.getString(Constants.IF_VULN_HOST) );
			if ( intfActive != null && intfActive.getSubnetId() == null && !intfActive.getAsset().getOrigin().equals("manual")) {
				assetsActive.add(intfActive.getAsset());
			}
			if (intfActive != null) {
				Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerability(v.getString(Constants.IF_VULN_NAME));
				ProjectVulnerability projectVulnerability = new ProjectVulnerability(intfActive,null,vulnerability,v.getString(Constants.IF_VULN_DESC),null
						,v.getString(Constants.IF_VULN_THREAT),v.getString(Constants.IF_VULN_PORT),null,null,vulnTemplate.SOURCE_NETWORK);
				projectVulnerability.updateStatusAndGrade(oldVulns, vulnTemplate);

				vulnTemplate.vulnerabilityPersist(oldVulns,projectVulnerability);
				//vulnTemplate.projectVulnerabilityRepository.save(projectVulnerability);
			} else  {
				log.error("Report contains ip {} which is not found in assets for project {}",v.getString(Constants.IF_VULN_HOST), ns.getProject().getName());
			}
		}
		log.debug("Successfully loaded report results - {}", vulns.length());


	}

	// TODO: wczytanie interfejsow dla assetu i stremami wyszukanie
	private Interface loadInterface(NessusScan ns, List<Asset> assets, String string) {
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
	public Interface createInterface (NessusScan ns, String ip, int size) {
		Interface intf = new Interface();
		Asset a = new Asset();
		log.debug("Adding unknown resource... {} - {}", ip, size);
		a.setName("Unknown Resource");
		a.setProject(ns.getProject());
		a.setOrigin("ServiceDiscovery");
		a.setActive(true);
		a.setRoutingDomain(ns.getProject().getAssets().iterator().next().getRoutingDomain());
		assetRepository.save(a);
		intf.setRoutingDomain(a.getRoutingDomain());
		intf.setFloatingip(ip);
		intf.setPrivateip(ip);
		intf.setAsset(a);
		intf.setAutoCreated(true);
		intf.setActive(true);
		interfaceRepository.save(intf);
		return intf;
	}

	private List<ProjectVulnerability> getProjectVulnerabilititiesByScan(NessusScan ns) {
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

	private static List<ProjectVulnerability> getInfrastructureVulns(NessusScan ns, List<Interface> intfs, List<ProjectVulnerability> tmpVulns, Long deleted, InterfaceRepository interfaceRepository, Logger log, ProjectVulnerabilityRepository projectVulnerabilityRepository) {
		assert intfs != null;
		for( Interface i : intfs) {
			tmpVulns.addAll(projectVulnerabilityRepository.findByAnInterface(i));
		}
		return tmpVulns;
	}

	private Boolean runAutomaticScan(NessusScan ns) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {

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
			nessusScanRepository.save(ns);
			log.debug("Starting running task");
			return runAutoScan(ns);

		}

		return false;
	}

	private Boolean runAutoScan(NessusScan ns) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
		try {
			RestRequestBody rrb = bodyPrepare(ns);
			HashMap<String, String> params = new HashMap<>();
			params.put(Constants.TASK_ID, ns.getTaskId());
			rrb.setParams(params);
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
			HttpHeaders headers = new HttpHeaders();
			headers.set("Content-Type", "application/json");
			HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(rrb),headers);
			ResponseEntity<String> response = restTemplate.exchange(ns.getNessus().getApiUrl() + "/starttask", HttpMethod.POST, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				ns.setReportId(new JSONObject(Objects.requireNonNull(response.getBody())).getString(Constants.REPORT_ID));
				ns.setRunning(true);
				nessusScanRepository.save(ns);
				return true;
			}
			else
				return false;
		} catch (HttpClientErrorException | HttpServerErrorException ex) {
			log.error("RunAutoScan HTTP exception {} for {}", ex.getRawStatusCode(), ns.getProject().getName());
		}
		return false;

	}

	private NessusScan createNewTask(NessusScan ns, RestRequestBody rrb) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
		HashMap<String, String> params = new HashMap<>();
		params.put(Constants.CONFIG_ID, ns.getNessus().getConfigId());
		params.put(Constants.SCANNER_ID, ns.getNessus().getScannerid());
		params.put(Constants.TARGET_ID, ns.getTargetId());
		params.put(Constants.TARGET_NAME,ns.getProject().getName()+"-"+(ns.getIsAutomatic()? Constants.SCAN_MODE_AUTO : Constants.SCAN_MODE_MANUAL));
		rrb.setParams(params);
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
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
	private NessusScan createNewTarget(NessusScan ns,RestRequestBody rrb) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
		try {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
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
	private HashMap<String, String> prepareCreateTarget(NessusScan ns) {
		HashMap<String,String> createTarget = new HashMap<>();
		List<String> ips;
		List<Asset> activeAssetsInProject = assetRepository.findByProjectAndActive(ns.getProject(), true);
		List<Interface> ifsWithFloating = interfaceRepository.findByAssetInAndFloatingipNotNull(activeAssetsInProject);
		List<Interface> ifsAll = interfaceRepository.findByAssetIn(activeAssetsInProject);
		if (ns.getIsAutomatic()) {
			if(ns.getNessus().getUsePublic()) {
				ips = ifsWithFloating.stream().filter(n -> n.getFloatingip() != null && !n.getAutoCreated()).map(Interface::getFloatingip).collect(Collectors.toList());
				ips.addAll(ifsAll.stream().filter(n -> n.getPrivateip() != null && !n.getAutoCreated()).map(Interface::getPrivateip).collect(Collectors.toList()));
				ips.addAll(ifsAll.stream().filter(n -> n.getPool() != null && !n.getAutoCreated()).map(Interface::getPool).collect(Collectors.toList()));
			} else {
				ips = ifsAll.stream().filter(n -> n.getPrivateip() != null && !n.getAutoCreated()).map(Interface::getPrivateip).collect(Collectors.toList());
				ips.addAll(ifsAll.stream().filter(n -> n.getPool() != null && !n.getAutoCreated()).map(Interface::getPool).collect(Collectors.toList()));
			}
		} else {
			if (ns.getNessus().getUsePublic()) {
				ips = ns.getInterfaces().stream().filter(n -> n.getFloatingip() != null && !n.getAutoCreated()).map(Interface::getFloatingip).collect(Collectors.toList());
				ips.addAll(ns.getInterfaces().stream().filter(n -> n.getPrivateip() != null && !n.getAutoCreated()).map(Interface::getPrivateip).collect(Collectors.toList()));
				ips.addAll(ifsAll.stream().filter(n -> n.getPool() != null && !n.getAutoCreated()).map(Interface::getPool).collect(Collectors.toList()));
			}
			else {
				ips = ns.getInterfaces().stream().filter(n -> n.getPrivateip() != null && !n.getAutoCreated()).map(Interface::getPrivateip).collect(Collectors.toList());
				ips.addAll(ifsAll.stream().filter(n -> n.getPool() != null && !n.getAutoCreated()).map(Interface::getPool).collect(Collectors.toList()));
			}
		}
		log.info("Scope of scan is [{}]: {}",ns.getNessus().getRoutingDomain().getName(), StringUtils.join(ips, ","));
		createTarget.put(Constants.TARGET_NAME, ns.getProject().getName()+"-"+(ns.getIsAutomatic()? Constants.SCAN_MODE_AUTO : Constants.SCAN_MODE_MANUAL)+"-"+UUID.randomUUID());
		createTarget.put(Constants.HOSTS, StringUtils.join(ips, ","));
		//TODO: Why doesnt work?
		//createTarget.put(Constants.HOSTS, StringUtils.join(scanHelper.prepareTargetsForScan(ns,true), ","));
		return createTarget;
	}
	public RestRequestBody bodyPrepare(NessusScan ns) {
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


	private void updateScannerInfo(io.mixeway.db.entity.Scanner nessus, String body) throws JSONException {
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
		List<Scanner> scanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS));
		return scanner.size() == 1 && scanner.get(0).getRoutingDomain().getId().equals(routingDomain.getId());

	}

	@Override
	public Scanner getScannerFromClient(RoutingDomain routingDomain) {
		List<Scanner> scanner = scannerRepository.findByScannerTypeAndRoutingDomain(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS), routingDomain);
		return scanner.stream().findFirst().orElse(null);
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
			io.mixeway.db.entity.Scanner nessus = new io.mixeway.db.entity.Scanner();
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
	private io.mixeway.db.entity.Scanner nessusOperations(Long domainId, Scanner nessus, Proxies proxy, String apiurl, ScannerType scannerType) throws Exception{
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

