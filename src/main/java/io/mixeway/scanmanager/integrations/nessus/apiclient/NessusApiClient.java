package io.mixeway.scanmanager.integrations.nessus.apiclient;

import com.google.gson.Gson;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.nessus.model.CreateFolderRequest;
import io.mixeway.scanmanager.integrations.nessus.model.CreateScanRequest;
import io.mixeway.scanmanager.service.SecurityScanner;
import io.mixeway.scanmanager.service.network.NetworkScanClient;
import io.mixeway.utils.ScanHelper;
import io.mixeway.utils.ScannerModel;
import io.mixeway.utils.SecureRestTemplate;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Component
@Log4j2
@RequiredArgsConstructor
public class NessusApiClient implements NetworkScanClient, SecurityScanner {
	private final VaultHelper vaultHelper;
	private final ScannerRepository scannerRepository;
	private final NessusScanTemplateRepository nessusScanTemplateRepository;
	private final AssetRepository assetRepository;
	private final InterfaceRepository interfaceRepository;
	private final InfraScanRepository infraScanRepository;
	private final ScanHelper scanHelper;
	private final SecureRestTemplate secureRestTemplate;
	private final ServiceRepository serviceRepository;
	private final StatusRepository statusRepository;
	private final ScannerTypeRepository scannerTypeRepository;
	private final RoutingDomainRepository routingDomainRepository;
	private final ProxiesRepository proxiesRepository;
	private final VulnTemplate vulnTemplate;
	List<Status> statusesNotRemoved;


	@Override
	public boolean initialize(Scanner scanner) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
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
	public boolean canProcessRequest(InfraScan infraScan) {
		return infraScan.getNessus().getScannerType().getName().equals(Constants.SCANNER_TYPE_NESSUS);
	}

	@Override
	public boolean canProcessRequest(Scanner scanner) {
		return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_NESSUS) && scanner.getStatus();
	}

	@Override
	public boolean canProcessInitRequest(Scanner scanner) {
		return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_NESSUS);
	}

	@Override
	public boolean canProcessRequest(RoutingDomain routingDomain) {
		List<Scanner> scanner = scannerRepository.findByScannerTypeAndRoutingDomain(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NESSUS), routingDomain);
		return scanner.size() > 0;
	}

	@Override
	public Scanner getScannerFromClient(RoutingDomain routingDomain) {
		List<Scanner> scanner = scannerRepository.findByScannerTypeAndRoutingDomain(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NESSUS), routingDomain);
		return scanner.stream().findFirst().orElse(null);

	}

	@Override
	public String printInfo() {
		return "Nessu Scanner";
	}

	@Override
	public boolean canProcessRequest(ScannerType scannerType) {
		return scannerType.getName().equals(Constants.SCANNER_TYPE_NESSUS);
	}

	@Override
	public Scanner saveScanner(ScannerModel scannerModel) throws Exception {
		ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
		Proxies proxy = null;
		if (scannerModel.getProxy() != 0)
			proxy = proxiesRepository.getOne(scannerModel.getProxy());
		Scanner nessus = new Scanner();
		nessusOperations(scannerModel.getRoutingDomain(),nessus,proxy,scannerModel.getApiUrl(),scannerType);
		// Secret key put to vault
		String uuidTokenAccess = UUID.randomUUID().toString();
		if (vaultHelper.savePassword(scannerModel.getAccesskey(), uuidTokenAccess)){
			nessus.setAccessKey(uuidTokenAccess);
		} else {
			nessus.setAccessKey(scannerModel.getAccesskey());
		}
		String uuidTokenSecret = UUID.randomUUID().toString();
		if (vaultHelper.savePassword(scannerModel.getSecretkey(), uuidTokenSecret)){
			nessus.setSecretKey(uuidTokenSecret);
		} else {
			nessus.setSecretKey(scannerModel.getSecretkey());
		}
		return scannerRepository.save(nessus);
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


	private HttpHeaders prepareAuthHeaderForNessus(Scanner scanner){
		HttpHeaders headers = new HttpHeaders();
		headers.set(Constants.NESSUS_APIKEYS, "accessKey="+
				vaultHelper.getPassword(scanner.getAccessKey())+"; secretKey="+
				vaultHelper.getPassword(scanner.getSecretKey()));
		return headers;
	}

	//TODO: String to objectModel maping
	private boolean getFolderId(Scanner scanner) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
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

	private void setFolderForNessus(Scanner scanner, String body) throws JSONException {
		scanner.setFolderId(new JSONObject(body).getInt(Constants.NESSUS_ID));
		scannerRepository.save(scanner);

	}

	//TODO: String to objectModel maping
	private boolean getTemplateUuid(Scanner scanner) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
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
	private void createScan(InfraScan infraScan) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		try {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(infraScan.getNessus());
			ResponseEntity<String> response = restTemplate.exchange(infraScan.getNessus().getApiUrl() + "/scans", HttpMethod.POST, prepareEntityForCreateUpdate(infraScan), String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				handleCreateScanResponse(infraScan, response.getBody());
			}
		} catch (HttpClientErrorException e) {
			log.error("Error during Nessus scan creation for {} - {} - {} - {} ", infraScan.getProject().getName(), e.getStatusCode(), infraScan.getNessus().getApiUrl() + "/scans", e.getResponseBodyAsString());
		}
	}
	private void deleteScan(InfraScan infraScan) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		try {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(infraScan.getNessus());
			HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeaderForNessus(infraScan.getNessus()));
			ResponseEntity<String> response = restTemplate.exchange(infraScan.getNessus().getApiUrl() + "/scans/"+ infraScan.getScanId(), HttpMethod.DELETE, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				infraScan.setScanId(0);
				infraScanRepository.save(infraScan);
			}
		} catch (HttpClientErrorException e) {
			log.error("Error during Nessus scan delete for {} - {} - {} - {} ", infraScan.getProject().getName(), e.getStatusCode(), infraScan.getNessus().getApiUrl() + "/scans", e.getResponseBodyAsString());
		}
	}
	//TODO: String to objectModel maping
	private HttpEntity<String> prepareEntityForCreateUpdate(InfraScan infraScan){
		HttpHeaders headers = prepareAuthHeaderForNessus(infraScan.getNessus());
		headers.set(Constants.HEADER_CONTENT_TYPE, Constants.HEADER_CONTENT_TYPE_JSON);
		return new HttpEntity<>(new Gson().toJson(prepareCreateScanRequest(infraScan)), headers);
	}
	//TODO: String to objectModel maping
	private void updateScan(InfraScan infraScan) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		try {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(infraScan.getNessus());
			ResponseEntity<String> response = restTemplate.exchange(infraScan.getNessus().getApiUrl() + "/scans/" + infraScan.getScanId(), HttpMethod.PUT,
					prepareEntityForCreateUpdate(infraScan), String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				log.info("Nessus Scan for {} is updated", infraScan.getProject().getName());
			} else {
				log.error("Error during Scan update for {} and {} - {}", infraScan.getNessus().getApiUrl(), infraScan.getProject().getName(), response.getStatusCode().toString());
			}
		} catch (HttpClientErrorException hcee){
			log.warn("Error during scan update for {} code {} msg {}", infraScan.getProject().getName(),hcee.getStatusCode(),hcee.getResponseBodyAsString());
		}
	}
	//TODO: String to objectModel maping
	private void launchScan(InfraScan infraScan) throws Exception {
		try {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(infraScan.getNessus());
			HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeaderForNessus(infraScan.getNessus()));

			ResponseEntity<String> response = restTemplate.exchange(infraScan.getNessus().getApiUrl() + "/scans/" + infraScan.getScanId() + "/launch", HttpMethod.POST, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				infraScan.setRunning(true);
				infraScanRepository.save(infraScan);
			}
		} catch (HttpClientErrorException e){
			log.error("Error during Scan Launching for {} - {} - {}", infraScan.getProject().getName(), e.getStatusCode(), infraScan.getNessus().getApiUrl() + "/scans/" + infraScan.getScanId() + "/launch");
			throw new Exception("Error during Scan Launching");
		}
	}

	private void handleCreateScanResponse(InfraScan infraScan, String body) throws JSONException {
		JSONObject response = new JSONObject(body);
		infraScan.setScanId(response.getJSONObject(Constants.NESSUS_SCAN).getInt(Constants.NESSUS_ID));
		infraScanRepository.save(infraScan);
		
	}

	@Transactional
	CreateScanRequest prepareCreateScanRequest(InfraScan infraScan) {
		String isAuto = infraScan.getIsAutomatic() ? "Automatic" : "Manual";
		List<String> targets = scanHelper.prepareTargetsForScan(infraScan,true);
		NessusScanTemplate nst = nessusScanTemplateRepository.findByNameAndNessus(Constants.NESSUS_TEMPLATE_BASIC_NETOWRK, infraScan.getNessus());
		return new CreateScanRequest(infraScan,nst.getUuid(), infraScan.getProject().getName()+"-"
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
	public boolean runScan(InfraScan infraScan) throws Exception {
		if (!infraScan.getRunning()) {
			runScanManual(infraScan);
			//this.launchScan(nessusScan);
			infraScan.setRunning(true);
			infraScanRepository.save(infraScan);
			return true;
		}
		else
			return false;
	}

	@Override
	public void runScanManual(InfraScan infraScan) throws Exception {
		try {
			if (infraScan.getScanId() == 0) {
				this.createScan(infraScan);
				this.launchScan(infraScan);
			} else {
				this.updateScan(infraScan);
				this.launchScan(infraScan);
			}
		} catch (Exception e){
			log.error(e.getLocalizedMessage());
		}
	}

	//TODO: String to objectModel maping
	@Transactional(propagation = Propagation.REQUIRES_NEW)
	public boolean isScanDone(InfraScan ns) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyStoreException, KeyManagementException {
		try {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(ns.getNessus());
			HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeaderForNessus(ns.getNessus()));
			ResponseEntity<String> response = restTemplate.exchange(ns.getNessus().getApiUrl() + "/scans/" + ns.getScanId(),
					HttpMethod.GET, entity, String.class);

			if (response.getStatusCode() == HttpStatus.OK) {
				String scanStatus = new JSONObject(Objects.requireNonNull(response.getBody())).getJSONObject(Constants.NESSUS_SCAN_INFO).getString(Constants.NESSUS_SCAN_STATUS);
				if (scanStatus.equals(Constants.NESSUS_SCAN_STATUS_COMPLETED) || scanStatus.equals(Constants.NESSUS_SCAN_STATUS_ABORTED)) {
					try {
						this.setHostsForInterfaces(response.getBody(), ns);
					} catch (JSONException ex) {
						ns.setRunning(false);
						infraScanRepository.save(ns);
						log.warn("Nessus scan completed for {} but no hosts found", ns.getProject().getName());
					}
					log.info("Scan for {} is done", ns.getProject().getName());
					return true;
				}
			} else {
				log.error("Getting scan results of scanner {} failed return code is: {}", ns.getNessus().getApiUrl(), response.getStatusCode().toString());
			}
		} catch (HttpClientErrorException e){
			log.error("Client Exception occured - {} - during scan status check for url {}", e.getStatusCode(),ns.getNessus().getApiUrl() + "/scans/" + ns.getScanId());
			ns.setRunning(false);
			infraScanRepository.save(ns);
		} catch (HttpServerErrorException e){
			log.error("Server Exception occured - {} - during scan status check for url {}", e.getStatusCode(),ns.getNessus().getApiUrl() + "/scans/" + ns.getScanId());
			ns.setRunning(false);
			infraScanRepository.save(ns);
		}
		return false;
	}


	public void setHostsForInterfaces(String body, InfraScan ns) throws JSONException {
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

	private Interface createAssetAndIntf(InfraScan ns, String string) {
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
	public void loadVulnerabilities(InfraScan ns) throws JSONException, CertificateException, UnrecoverableKeyException,
			NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		List<Interface> intfs = interfaceRepository.getInterfaceForAssetsWithHostIdSet(assetRepository.findByProjectAndRoutingDomain(ns.getProject(),ns.getNessus().getRoutingDomain()));
		List<ProjectVulnerability> oldVulns = vulnTemplate.projectVulnerabilityRepository.findByanInterfaceIn(intfs).collect(Collectors.toList());
		for (Interface i : intfs) {
			this.loadVulnForInterface(ns, i);
		}
		List<ProjectVulnerability> newVulns = vulnTemplate.projectVulnerabilityRepository.findByanInterfaceInAndStatusIn(intfs, statusesNotRemoved);
		if (ns.getRetries() < 3 && oldVulns.size() > newVulns.size()){
			ns.setRunning(true);
			ns.setRetries(ns.getRetries() + 1);
			log.info("Possible problem with Scan for {} - vulnerability count is lower, setting retries to {}", ns.getProject().getName(), ns.getRetries());
		} else {
			ns.setRunning(false);
			ns.setRetries(0);
			log.info("Nessus - successfully loaded vulnerabilities for {}",ns.getProject().getName());
		}
		infraScanRepository.saveAndFlush(ns);

		if (!ns.getIsAutomatic()){
			//this.deleteScan(ns);
		}
		//scanHelper.updateInterfaceState(ns,false);
	}

	public void loadVulnForInterface(InfraScan ns, Interface i) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		try {
			List<ProjectVulnerability> tmpOldVulns = vulnTemplate.projectVulnerabilityRepository.findByAnInterface(i);
			if (tmpOldVulns.size() > 0)
				vulnTemplate.projectVulnerabilityRepository.updateVulnState(tmpOldVulns.stream().map(ProjectVulnerability::getId).collect(Collectors.toList()),
						vulnTemplate.STATUS_REMOVED.getId());

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
		} catch (HttpClientErrorException e){
			log.error("Client Exception - {} - during loading vulnerabilities for {}", e.getStatusCode(), ns.getNessus().getApiUrl() + "/scans/" + ns.getScanId() + "/hosts/" + i.getHostid());
		}
		
	}


	private void createVulnerability(JSONObject vuln, InfraScan ns, Interface i, List<ProjectVulnerability> oldVulns) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		int pluginid = vuln.getInt(Constants.NESSUS_PLUGIN_ID);
		String pluginName = vuln.getString(Constants.NESSUS_PLUGIN_NAME);
		Map<Integer,String> pluginVulns = new HashMap<>();
		if (pluginVulns.containsKey(pluginid)) {
			createVuln(vuln, i, pluginVulns.get(pluginid), pluginName, oldVulns);
		} else {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(ns.getNessus());
			HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeaderForNessus(ns.getNessus()));
			ResponseEntity<String> response = restTemplate.exchange(ns.getNessus().getApiUrl() + "/scans/" + ns.getScanId() + "/hosts/" + i.getHostid() + "/plugins/" + pluginid,
					HttpMethod.GET, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				createVuln(vuln, i, response.getBody(), pluginName, oldVulns);
				pluginVulns.put(pluginid, response.getBody());
			} else {
				log.error("Getting plugins {} failed return code is - {}", ns.getNessus().getApiUrl(), response.getStatusCode().toString());
			}
		}
	}

	private void createVuln(JSONObject vuln, Interface i, String body, String pluginName, List<ProjectVulnerability> oldVulns) throws JSONException {
		JSONObject bodyJ = new JSONObject(body);
		List<ProjectVulnerability> projectVulnerabilities = new ArrayList<>();
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
					Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerability(vuln.getString(Constants.NESSUS_PLUGIN_NAME));
					ProjectVulnerability projectVulnerability = new ProjectVulnerability(i, null, vulnerability,bodyJ.getJSONObject(Constants.NESSUS_SCAN_INFO).getJSONObject(Constants.NESSUS_PLUGINDESCRIPTION)
							.getJSONObject(Constants.NESSUS_PLUGINATTRIBUTES).getString(Constants.NESSUS_VULN_DESCRIPTION),
							null,threat, key,null,null, vulnTemplate.SOURCE_NETWORK,null,null);
					projectVulnerability.updateStatusAndGrade(oldVulns, vulnTemplate);

					projectVulnerabilities.add(projectVulnerability);
				}
			}
			vulnTemplate.vulnerabilityPersistList(oldVulns, projectVulnerabilities);

		} catch (JSONException ex) {
			log.error("Exception for {} {} {}",i.getPrivateip(),i.getHostid(),ex.getLocalizedMessage());
		}
	}
	private void createServicesForInterface(Interface i){

		serviceRepository.updateServiceSetStatusNullForInterface(i.getId());
		List<Service> services = serviceRepository.findByAnInterface(i);
		for (String port : vulnTemplate.projectVulnerabilityRepository.getPortsFromInfraVulnForInterface(i)){
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
