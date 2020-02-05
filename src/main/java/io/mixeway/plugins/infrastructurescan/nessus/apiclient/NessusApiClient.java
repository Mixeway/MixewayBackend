package io.mixeway.plugins.infrastructurescan.nessus.apiclient;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.infrastructurescan.service.NetworkScanClient;
import io.mixeway.plugins.infrastructurescan.service.NetworkScanService;
import io.mixeway.plugins.remotefirewall.apiclient.RfwApiClient;
import io.mixeway.pojo.ScanHelper;
import io.mixeway.pojo.SecureRestTemplate;
import io.mixeway.pojo.SecurityScanner;
import io.mixeway.rest.model.ScannerModel;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponseSupport;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import com.google.gson.Gson;

import io.mixeway.plugins.infrastructurescan.nessus.model.CreateFolderRequest;
import io.mixeway.plugins.infrastructurescan.nessus.model.CreateScanRequest;

@Component
public class NessusApiClient implements NetworkScanClient, SecurityScanner {
	private final static Logger log = LoggerFactory.getLogger(NessusApiClient.class);
	private final VaultOperations operations;
	private final ScannerRepository scannerRepository;
	private final NessusScanTemplateRepository nessusScanTemplateRepository;
	private final AssetRepository assetRepository;
	private final InterfaceRepository interfaceRepository;
	private final NessusScanRepository nessusScanRepository;
	private final InfrastructureVulnRepository infrastructureVulnRepository;
	private final RfwApiClient rfwApiClient;
	private final ScanHelper scanHelper;
	private final SecureRestTemplate secureRestTemplate;
	private final ServiceRepository serviceRepository;
	private final StatusRepository statusRepository;
	private final ScannerTypeRepository scannerTypeRepository;
	private final RoutingDomainRepository routingDomainRepository;
	private final ProxiesRepository proxiesRepository;
	private final NetworkScanService networkScanService;
	@Autowired
	@Lazy
	NessusApiClient(VaultOperations operations, ScannerRepository scannerRepository, NessusScanTemplateRepository nessusScanTemplateRepository,
					AssetRepository assetRepository, InterfaceRepository interfaceRepository, NessusScanRepository nessusScanRepository,
					InfrastructureVulnRepository infrastructureVulnRepository, RfwApiClient rfwApiClient, ScanHelper scanHelper, NetworkScanService networkScanService,
					SecureRestTemplate secureRestTemplate, ServiceRepository serviceRepository, StatusRepository statusRepository,
					ScannerTypeRepository scannerTypeRepository, RoutingDomainRepository routingDomainRepository, ProxiesRepository proxiesRepository){
		this.operations = operations;
		this.scannerRepository = scannerRepository;
		this.nessusScanRepository = nessusScanRepository;
		this.assetRepository = assetRepository;
		this.interfaceRepository = interfaceRepository;
		this.nessusScanTemplateRepository = nessusScanTemplateRepository;
		this.infrastructureVulnRepository = infrastructureVulnRepository;
		this.networkScanService = networkScanService;
		this.rfwApiClient = rfwApiClient;
		this.scanHelper = scanHelper;
		this.secureRestTemplate = secureRestTemplate;
		this.serviceRepository = serviceRepository;
		this.statusRepository = statusRepository;
		this.routingDomainRepository = routingDomainRepository;
		this.scannerTypeRepository = scannerTypeRepository;
		this.proxiesRepository = proxiesRepository;
	}
	@Override
	public boolean initialize(io.mixeway.db.entity.Scanner scanner) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		try {
			if (getTemplateUuid(scanner) && getFolderId(scanner)) {
				scanner.setStatus(true);
				scannerRepository.save(scanner);
				return true;
			}
		} catch (HttpClientErrorException ex){
			log.error("Error occured during nessus initialize - {} - {} {}", scanner.getApiUrl(), ex.getStatusCode(), ex.getLocalizedMessage() );
		}
		return false;
	}

	@Override
	public boolean canProcessRequest(NessusScan nessusScan) {
		return nessusScan.getNessus().getScannerType().getName().equals(Constants.SCANNER_TYPE_NESSUS);
	}

	@Override
	public boolean canProcessRequest(io.mixeway.db.entity.Scanner scanner) {
		return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_NESSUS);
	}

	@Override
	public boolean canProcessRequest(ScannerType scannerType) {
		return scannerType.getName().equals(Constants.SCANNER_TYPE_NESSUS);
	}

	@Override
	public void saveScanner(ScannerModel scannerModel) throws Exception {
		ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
		Proxies proxy = null;
		if (scannerModel.getProxy() != 0)
			proxy = proxiesRepository.getOne(scannerModel.getProxy());
		io.mixeway.db.entity.Scanner nessus = new io.mixeway.db.entity.Scanner();
		nessus.setAccessKey(UUID.randomUUID().toString());
		nessus.setSecretKey(UUID.randomUUID().toString());
		nessusOperations(scannerModel.getRoutingDomain(),nessus,proxy,scannerModel.getApiUrl(),scannerType);
		// Secret key put to vault
		Map<String, String> secretKeyMap = new HashMap<>();
		secretKeyMap.put("password", scannerModel.getSecretkey());
		operations.write("secret/"+nessus.getSecretKey(), secretKeyMap);
		// Access key put to vault
		secretKeyMap = new HashMap<>();
		secretKeyMap.put("password", scannerModel.getAccesskey());
		operations.write("secret/"+nessus.getAccessKey(), secretKeyMap);
	}
	private io.mixeway.db.entity.Scanner nessusOperations(Long domainId, io.mixeway.db.entity.Scanner nessus, Proxies proxy, String apiurl, ScannerType scannerType) throws Exception{
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


	private HttpHeaders prepareAuthHeaderForNessus(io.mixeway.db.entity.Scanner scanner){
		VaultResponseSupport<Map<String,Object>> secretKey = operations.read("secret/"+scanner.getSecretKey());
		VaultResponseSupport<Map<String,Object>> accessKey = operations.read("secret/"+scanner.getAccessKey());
		HttpHeaders headers = new HttpHeaders();
		assert accessKey != null;
		assert secretKey != null;
		headers.set(Constants.NESSUS_APIKEYS, "accessKey="+
				Objects.requireNonNull(accessKey.getData())
						.get("password")
						.toString()+"; secretKey="+
				Objects.requireNonNull(secretKey.getData())
						.get("password")
						.toString());
		return headers;
	}
	
	//TODO: String to objectModel maping
	private boolean getFolderId(io.mixeway.db.entity.Scanner scanner) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
		HttpHeaders headers = prepareAuthHeaderForNessus(scanner);
		headers.set(Constants.HEADER_CONTENT_TYPE, Constants.HEADER_CONTENT_TYPE_JSON);
		HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(new CreateFolderRequest()),headers);
		try {
			ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/folders", HttpMethod.POST, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				setFolderForNessus(scanner, response.getBody());
				return true;
			} else {
				return false;
			}
		} catch (HttpClientErrorException e){
			if (e.getStatusCode().equals(HttpStatus.CONFLICT)){
				log.warn("Nessus {} responded with CONFLICT state during folder creation, returning true, hopeing that there is already folderID created", scanner.getApiUrl());
				return true;
			} else {
				return false;
			}
		}
	}

	private void setFolderForNessus(io.mixeway.db.entity.Scanner scanner, String body) throws JSONException {
		scanner.setFolderId(new JSONObject(body).getInt(Constants.NESSUS_ID));
		scannerRepository.save(scanner);
		
	}

	//TODO: String to objectModel maping
	private boolean getTemplateUuid(io.mixeway.db.entity.Scanner scanner) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
		HttpHeaders headers = prepareAuthHeaderForNessus(scanner);
		HttpEntity<String> entity = new HttpEntity<>(headers);
		ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/editor/scan/templates", HttpMethod.GET, entity, String.class);
		if (response.getStatusCode() == HttpStatus.OK) {
			setScanTemplate(scanner, response.getBody());
			return true;
		}
		else {
			log.error("Initialization of scanner {} failed return code is: {}",scanner.getApiUrl(),response.getStatusCode().toString());
			return false;
		}
	}

	//TODO: String to objectModel maping
	private void createScan(NessusScan nessusScan) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		RestTemplate restTemplate =secureRestTemplate.prepareClientWithCertificate(nessusScan.getNessus());
		ResponseEntity<String> response = restTemplate.exchange(nessusScan.getNessus().getApiUrl() + "/scans", HttpMethod.POST, prepareEntityForCreateUpdate(nessusScan), String.class);
		if (response.getStatusCode() == HttpStatus.OK) {
			handleCreateScanResponse(nessusScan, response.getBody());
		}
		else {
			log.error("Error during Scan creation for {} and {} - {}",nessusScan.getNessus().getApiUrl(),nessusScan.getProject().getName(),response.getStatusCode().toString());
		}
	}
	//TODO: String to objectModel maping
	private HttpEntity<String> prepareEntityForCreateUpdate(NessusScan nessusScan){
		HttpHeaders headers = prepareAuthHeaderForNessus(nessusScan.getNessus());
		headers.set(Constants.HEADER_CONTENT_TYPE, Constants.HEADER_CONTENT_TYPE_JSON);
		return new HttpEntity<>(new Gson().toJson(prepareCreateScanRequest(nessusScan)), headers);
	}
	//TODO: String to objectModel maping
	private void updateScan(NessusScan nessusScan) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		try {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(nessusScan.getNessus());
			ResponseEntity<String> response = restTemplate.exchange(nessusScan.getNessus().getApiUrl() + "/scans/" + nessusScan.getScanId(), HttpMethod.PUT,
					prepareEntityForCreateUpdate(nessusScan), String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				log.info("Nessus Scan for {} is updated", nessusScan.getProject().getName());
			} else {
				log.error("Error during Scan update for {} and {} - {}", nessusScan.getNessus().getApiUrl(), nessusScan.getProject().getName(), response.getStatusCode().toString());
			}
		} catch (HttpClientErrorException hcee){
			log.warn("Error during scan update for {} code {} msg {}", nessusScan.getProject().getName(),hcee.getStatusCode(),hcee.getResponseBodyAsString());
		}
	}
	//TODO: String to objectModel maping
	private void launchScan(NessusScan nessusScan) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException,
			KeyManagementException, KeyStoreException, IOException {
		try {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(nessusScan.getNessus());
			HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeaderForNessus(nessusScan.getNessus()));
			if (nessusScan.getNessus().getRfwUrl() != null) {
				this.putRulesOnRfw(nessusScan);
				log.info("RFW for scan {} is configured - accept traffic", nessusScan.getProject().getName());
			}

			ResponseEntity<String> response = restTemplate.exchange(nessusScan.getNessus().getApiUrl() + "/scans/" + nessusScan.getScanId() + "/launch", HttpMethod.POST, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				nessusScan.setRunning(true);
				nessusScanRepository.save(nessusScan);
			} else {
				log.error("Error during Scan Launching for {} and {} - {}", nessusScan.getNessus().getApiUrl(), nessusScan.getProject().getName(), response.getStatusCode().toString());
			}
		} catch (HttpClientErrorException e){
			log.error("Error during Scan Launching for {} and {}", nessusScan.getNessus().getApiUrl(), nessusScan.getProject().getName());
		}
	}
	private void putRulesOnRfw(NessusScan nessusScan)throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		for (String ipAddress : scanHelper.prepareTargetsForScan(nessusScan,false)){
			rfwApiClient.operateOnRfwRule(nessusScan.getNessus(),ipAddress,HttpMethod.PUT);
		}
	}
	public void deleteRulsFromRfw(NessusScan nessusScan)throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		for (String ipAddress : scanHelper.prepareTargetsForScan(nessusScan,false)){
			rfwApiClient.operateOnRfwRule(nessusScan.getNessus(),ipAddress,HttpMethod.DELETE);
		}
	}

	private void handleCreateScanResponse(NessusScan nessusScan, String body) throws JSONException {
		JSONObject response = new JSONObject(body);
		nessusScan.setScanId(response.getJSONObject(Constants.NESSUS_SCAN).getInt(Constants.NESSUS_ID));
		nessusScanRepository.save(nessusScan);
		
	}

	private CreateScanRequest prepareCreateScanRequest(NessusScan nessusScan) {
		String isAuto = nessusScan.getIsAutomatic() ? "Automatic" : "Manual";
		List<String> targets = scanHelper.prepareTargetsForScan(nessusScan,true);
		NessusScanTemplate nst = nessusScanTemplateRepository.findByNameAndNessus(Constants.NESSUS_TEMPLATE_BASIC_NETOWRK, nessusScan.getNessus());
		return new CreateScanRequest(nessusScan,nst.getUuid(), nessusScan.getProject().getName()+"-"
				+isAuto+"-"+UUID.randomUUID().toString(), "Scan run from mixer", targets);
	}



	private void setScanTemplate(Scanner scanner, String body) throws JSONException {
		JSONObject response = new JSONObject(body);
		JSONArray tmplates = response.getJSONArray(Constants.NESSUS_TEMPLATES);
		for (int i = 0; i < tmplates.length(); i++) {
			JSONObject template = tmplates.getJSONObject(i);
			NessusScanTemplate nst = new NessusScanTemplate();
			nst.setName(template.getString(Constants.NESSUS_TEMPLATE_TITLE));
			nst.setNessus(scanner);
			nst.setUuid(template.getString(Constants.NESSUS_UUID));
			nessusScanTemplateRepository.save(nst);
		}
		
	}

	@Override
	public boolean runScan(NessusScan nessusScan) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		if (!nessusScan.getRunning()) {
			runScanManual(nessusScan);
			//this.launchScan(nessusScan);
			nessusScan.setRunning(true);
			nessusScanRepository.save(nessusScan);
			return true;
		}
		else
			return false;
	}

	@Override
	public void runScanManual(NessusScan nessusScan) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, IOException {
		if (nessusScan.getScanId() == 0) {
			this.createScan(nessusScan);
			this.launchScan(nessusScan);
		} else {
			this.updateScan(nessusScan);
			this.launchScan(nessusScan);
		}
	}

	//TODO: String to objectModel maping
	public boolean isScanDone(NessusScan ns) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyStoreException, KeyManagementException {
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(ns.getNessus());
		HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeaderForNessus(ns.getNessus()));
		ResponseEntity<String> response = restTemplate.exchange(ns.getNessus().getApiUrl() + "/scans/"+ns.getScanId(),
				HttpMethod.GET, entity, String.class);
		
		if (response.getStatusCode() == HttpStatus.OK) {
			String scanStatus = new JSONObject(Objects.requireNonNull(response.getBody())).getJSONObject(Constants.NESSUS_SCAN_INFO).getString(Constants.NESSUS_SCAN_STATUS);
			if (scanStatus.equals(Constants.NESSUS_SCAN_STATUS_COMPLETED) || scanStatus.equals(Constants.NESSUS_SCAN_STATUS_ABORTED)) {
				try {
					this.setHostsForInterfaces(response.getBody(),ns);
				} catch (JSONException ex) {
					ns.setRunning(false);
					nessusScanRepository.save(ns);
					log.warn("Nessus scan completed for {} but no hosts found", ns.getProject().getName());
				}
				log.info("Scan for {} is done",ns.getProject().getName());
				return true;
			}
			else return false;
		}
		else {
			log.error("Getting scan results of scanner {} failed return code is: {}",ns.getNessus().getApiUrl(),response.getStatusCode().toString());
			return false;
		}
	}


	private void setHostsForInterfaces(String body,NessusScan ns) throws JSONException {
		JSONObject response = new JSONObject(body);
		
		JSONArray hosts = response.getJSONArray(Constants.NESSUS_HOSTS);
		for (int i = 0; i < hosts.length(); i++) {
			JSONObject host = hosts.getJSONObject(i);
			List<Asset> assets = assetRepository.getAssetForProjectByNativeQuery(ns.getProject().getId());
			Interface intf = findInterfaceForIp(host.getString(Constants.NESSUS_HOSTNAME),assets);
			if (intf == null){
				intf = createAssetAndIntf(ns, host.getString(Constants.NESSUS_HOSTNAME));
			}
			intf.setHostid(host.getInt(Constants.NESSUS_HOST_ID));
			Asset asset =intf.getAsset();
			asset.setRequestId(ns.getRequestId());
			assetRepository.save(asset);
			interfaceRepository.save(intf);
		}
		log.debug("Nessus Scan for {} completed and {} hosts were scanned",ns.getProject().getName(),hosts.length());
		
	}

	private Interface createAssetAndIntf(NessusScan ns, String string) {
		Asset a = new Asset();
		a.setProject(ns.getProject());
		a.setRoutingDomain(ns.getNessus().getRoutingDomain());
		a.setActive(true);
		a.setOrigin("auto");
		a.setName(string);
		a = assetRepository.save(a);
		Interface intf  = new Interface();
		intf.setAsset(a);
		intf.setPrivateip(string);
		intf.setActive(true);
		intf.setAutoCreated(true);
		intf.setRoutingDomain(a.getRoutingDomain());
		intf = interfaceRepository.save(intf);
		return intf;

	}


	private Interface findInterfaceForIp(String string,List<Asset> assets) {
		try {
			List<Interface> interfacesInAssets = interfaceRepository.findByAssetIn(assets);
			Optional<Interface> intefaceMatchingPatter;
			intefaceMatchingPatter = interfacesInAssets.stream().filter(p -> p.getFloatingip() != null).filter(p -> p.getFloatingip().equals(string)).findFirst();
			if (!intefaceMatchingPatter.isPresent())
				intefaceMatchingPatter = interfacesInAssets.stream().filter(p -> p.getPrivateip().equals(string)).findFirst();
			if (intefaceMatchingPatter.isPresent())
				return intefaceMatchingPatter.get();
		} catch (NullPointerException e){
			log.error("nullpointer line 330, for string {}",string);
		}
		return null;
	}


	@Override
	@Transactional(propagation = Propagation.REQUIRED, isolation = Isolation.SERIALIZABLE)
	public void loadVulnerabilities(NessusScan ns) throws JSONException, CertificateException, UnrecoverableKeyException,
			NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		List<Interface> intfs = interfaceRepository.getInterfaceForAssetsWithHostIdSet(new ArrayList<>(ns.getProject().getAssets()));
		for (Interface i : intfs) {
			this.loadVulnForInterface(ns, i);
		}
		ns.setRunning(false);
		nessusScanRepository.saveAndFlush(ns);
		if (ns.getNessus().getRfwUrl() != null) {
			networkScanService.deleteRulsFromRfw(ns);
			log.info("RFW for scan {} is cleared - dropped traffic", ns.getProject().getName());
		}
		log.info("Nessus - successfully loaded vulnerabilities for {}",ns.getProject().getName());
		//scanHelper.updateInterfaceState(ns,false);
	}

	private void loadVulnForInterface(NessusScan ns, Interface i) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		try {
			i.getVulns().clear();
			List<InfrastructureVuln> tmpOldVulns = infrastructureVulnRepository.findByIntf(i);
			infrastructureVulnRepository.deleteByIntf(i);
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(ns.getNessus());
			HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeaderForNessus(ns.getNessus()));
			ResponseEntity<String> response = restTemplate.exchange(ns.getNessus().getApiUrl() + "/scans/" + ns.getScanId() + "/hosts/" + i.getHostid(),
					HttpMethod.GET, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				JSONArray vulnArray = new JSONObject(Objects.requireNonNull(response.getBody())).getJSONArray(Constants.NESSUS_VULNERABILITIES);
				for (int k = 0; k < vulnArray.length(); k++) {
					JSONObject vuln = vulnArray.getJSONObject(k);
					createVulnerability(vuln, ns, i, tmpOldVulns);
				}
				createServicesForInterface(i);
			} else {
				log.error("Getting vulns {} failed return code is: {}", ns.getNessus().getApiUrl(), response.getStatusCode().toString());
			}
			i.setHostid(0);
			i.setScanRunning(false);
			interfaceRepository.saveAndFlush(i);
		} catch (NullPointerException e){
			log.warn("Nullpoitnter during loading vuln for project {} asset {}", i.getAsset().getProject().getName(),i.getAsset().getName());
		}
		
	}


	private void createVulnerability(JSONObject vuln, NessusScan ns, Interface i, List<InfrastructureVuln> oldVulns) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		int pluginid = vuln.getInt(Constants.NESSUS_PLUGIN_ID);
		String pluginName = vuln.getString(Constants.NESSUS_PLUGIN_NAME);
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(ns.getNessus());
		HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeaderForNessus(ns.getNessus()));
		ResponseEntity<String> response = restTemplate.exchange(ns.getNessus().getApiUrl() + "/scans/"+ns.getScanId()+"/hosts/"+i.getHostid()+"/plugins/"+pluginid,
				HttpMethod.GET, entity, String.class);
		if (response.getStatusCode() == HttpStatus.OK) {
			createVuln(vuln, i, response.getBody(), pluginName,oldVulns);
		}
		else {
			log.error("Getting plugins {} failed return code is - {}",ns.getNessus().getApiUrl(),response.getStatusCode().toString());
		}
		
	}

	private void createVuln(JSONObject vuln, Interface i, String body, String pluginName, List<InfrastructureVuln> oldVulns) throws JSONException {
		JSONObject bodyJ = new JSONObject(body);
		try {
			JSONArray outputs = bodyJ.getJSONArray(Constants.NESSUS_OUTPUTS);
			for (int k = 0; k < outputs.length(); k++) {
				JSONObject output = outputs.getJSONObject(k).getJSONObject(Constants.NESSUS_PORTS);

				if(pluginName.equals(Constants.NESSUS_OS_IDENTIFICATION)){
					Pattern regex = Pattern.compile(".*Remote operating system : (.*)Confi.*", Pattern.DOTALL);
					String pluginOutput = outputs.getJSONObject(k).getString(Constants.NESSUS_PLUGIN_OUTPUT);
					Matcher regexMatcher = regex.matcher(pluginOutput);
					while(regexMatcher.find()){
						i.getAsset().setOs(regexMatcher.group(1).replace("\n",","));
						assetRepository.save(i.getAsset());
					}
				}

				JSONArray keys = output.names ();
				for (int j = 0; j < keys.length (); ++j) {
					String threat;
					String key = keys.getString (j); 
					InfrastructureVuln iv = new InfrastructureVuln();
					iv.setIntf(i);
					iv.setDescription(bodyJ.getJSONObject(Constants.NESSUS_SCAN_INFO).getJSONObject(Constants.NESSUS_PLUGINDESCRIPTION)
						   .getJSONObject(Constants.NESSUS_PLUGINATTRIBUTES).getString(Constants.NESSUS_VULN_DESCRIPTION));
					iv.setName(vuln.getString(Constants.NESSUS_PLUGIN_NAME));
					iv.setPort(key);
					iv.setInserted(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
					if (vuln.getInt(Constants.NESSUS_SEVERITY) == 0)
						threat = "Info";
					else if (vuln.getInt(Constants.NESSUS_SEVERITY) == 1)
						threat = "Low";
					else if (vuln.getInt(Constants.NESSUS_SEVERITY) == 2)
						threat = "Medium";
					else if (vuln.getInt(Constants.NESSUS_SEVERITY) == 3)
						threat = "High";
					else
						threat = "Critical";
					iv.setSeverity(threat);
					if (oldVulns.stream().anyMatch(v -> v.getName().equals(iv.getName()) && v.getDescription().equals(iv.getDescription())
					&& v.getSeverity().equals(iv.getSeverity()) && v.getPort().equals(iv.getPort()))){
						iv.setStatus(statusRepository.findByName(Constants.STATUS_EXISTING));
					} else {
						iv.setStatus(statusRepository.findByName(Constants.STATUS_NEW));
					}
					infrastructureVulnRepository.save(iv);
	
				}
			}

		} catch (JSONException ex) {
			log.error("Exception for {} {} {}",i.getPrivateip(),i.getHostid(),ex.getLocalizedMessage());
		}
	}
	private void createServicesForInterface(Interface i){

		serviceRepository.updateServiceSetStatusNullForInterface(i.getId());
		List<Service> services = serviceRepository.findByAnInterface(i);
		for (String port : infrastructureVulnRepository.getPortsFromInfraVulnForInterface(i.getId())){
			String[] splitedPort = port.split("/");
			Optional<Service> optionalService = services.stream().filter(s -> s.getAppProto().equals(splitedPort[2].trim()) && s.getNetProto().equals(splitedPort[1].trim()) &&
					s.getPort()==Integer.parseInt(splitedPort[0].trim())).findFirst();
			if (optionalService.isPresent()){
				optionalService.get().setStatus(statusRepository.findByName(Constants.STATUS_EXISTING));
				serviceRepository.save(optionalService.get());
			} else {
				Service newService = new Service();
				newService.setStatus(statusRepository.findByName(Constants.STATUS_NEW));
				newService.setAnInterface(i);
				newService.setPort(Integer.parseInt(splitedPort[0].trim()));
				newService.setNetProto(splitedPort[1].trim());
				newService.setAppProto(splitedPort[2].trim());
				serviceRepository.save(newService);
			}
		}
		serviceRepository.removeOldServices(i.getId());
	}
	

}
