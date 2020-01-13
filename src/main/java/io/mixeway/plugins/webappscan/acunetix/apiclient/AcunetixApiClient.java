package io.mixeway.plugins.webappscan.acunetix.apiclient;


import java.text.SimpleDateFormat;
import java.util.*;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.webappscan.WebAppScanClient;
import io.mixeway.plugins.webappscan.acunetix.model.AcunetixSeverity;
import io.mixeway.plugins.webappscan.model.*;
import io.mixeway.pojo.SecureRestTemplate;
import io.mixeway.pojo.SecurityScanner;
import io.mixeway.rest.model.ScannerModel;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.postgresql.util.PSQLException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponseSupport;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.gson.Gson;
import javax.transaction.Transactional;


@Service
public class AcunetixApiClient implements WebAppScanClient, SecurityScanner {
	private final static Logger log = LoggerFactory.getLogger(AcunetixApiClient.class);
	private final VaultOperations operations;
	private final WebAppRepository webAppRepository;
	private final WebAppVulnRepository webAppVulnRepository;
	private final SecureRestTemplate secureRestTemplate;
	private final StatusRepository statusRepository;
	private final RoutingDomainRepository routingDomainRepository;
	private final ScannerRepository scannerRepository;
	private final ScannerTypeRepository scannerTypeRepository;
	private final ProxiesRepository proxiesRepository;

	@Autowired
	AcunetixApiClient(VaultOperations operations, WebAppRepository webAppRepository, WebAppVulnRepository webAppVulnRepository,
					  SecureRestTemplate secureRestTemplate, StatusRepository statusRepository, RoutingDomainRepository routingDomainRepository,
					  ScannerRepository scannerRepository, ScannerTypeRepository scannerTypeRepository, ProxiesRepository proxiesRepository){
		this.operations = operations;
		this.webAppRepository = webAppRepository;
		this.routingDomainRepository = routingDomainRepository;
		this.scannerRepository = scannerRepository;
		this.webAppVulnRepository = webAppVulnRepository;
		this.secureRestTemplate = secureRestTemplate;
		this.statusRepository = statusRepository;
		this.proxiesRepository = proxiesRepository;
		this.scannerTypeRepository = scannerTypeRepository;

	}

	private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	
	private HttpHeaders prepareAuthHeader(io.mixeway.db.entity.Scanner scanner) throws Exception {
		if (scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_ACUNETIX)) {
			VaultResponseSupport<Map<String,Object>> password = operations.read("secret/"+scanner.getApiKey());
			HttpHeaders headers = new HttpHeaders();
			assert password != null;
			headers.set("X-Auth", Objects.requireNonNull(password.getData()).get("password").toString());
			return headers;
		} else
			throw new Exception("Trying to prepare auth for non acunetix scanner. Somtheing went wrong..");
	}
	@Override
	@org.springframework.transaction.annotation.Transactional(propagation = Propagation.REQUIRES_NEW)
	public void configureWebApp(WebApp webApp, io.mixeway.db.entity.Scanner scanner) throws Exception   {
		//try {
			Long count = webAppRepository.getCountOfRunningScans(true);
			Boolean isDuplicatedUrl = checkDuplicateRunning(webApp);
			if (count <= Constants.ACUNETIX_TARGET_LIMIT && !webApp.getRunning() && isDuplicatedUrl) {
				this.createTarget(scanner, webApp);
				if (webApp.getLoginSequence() != null) {
					this.createLoginSequenceUrl(scanner, webApp);
					this.uploadLoginSequenceForTarget(scanner, webApp);
				}
				if ((webApp.getHeaders() != null) && (webApp.getHeaders().size() > 0))
					this.createHeadersForTarget(scanner, webApp);
				if ((webApp.getWebAppCookies() != null) && (webApp.getWebAppCookies().size() > 0))
					this.createCookiesorTarget(scanner, webApp);

				if (webApp.getPublicscan())
					this.createProxyForWebApp(scanner, webApp);
				this.runScan(webApp,scanner);
			} else if (isDuplicatedUrl && (count > Constants.ACUNETIX_TARGET_LIMIT) && !webApp.getRunning()) {
				log.debug("Acunetix limit is nearly done - {}. Putting webapp to queue.", count);
				webApp.setInQueue(true);
				webAppRepository.save(webApp);
			} else
				log.debug("WebApp rest api scan omitting.. {}", webApp.getUrl());
		//}
	}
	private Boolean checkDuplicateRunning(WebApp webApp) {
		List<WebApp> runningWebApps = webAppRepository.findByRunning(true);
		
			
		for (WebApp runningWebApp : runningWebApps) {
			try {
				String webAppUrl = webApp.getUrl().substring(0, webApp.getUrl().lastIndexOf("?"));
				String runningWebAppUrl =  runningWebApp.getUrl().substring(0, runningWebApp.getUrl().lastIndexOf("?"));
				if (runningWebAppUrl.equals(webAppUrl)) {
					log.info("Found duplicate URL {} omitting..", runningWebAppUrl);
					return false;
				}
			}catch (IndexOutOfBoundsException ignored) {
			}
		}
		
		return true;
	}
	//TODO Object mapping
	@Override
	public boolean initialize(io.mixeway.db.entity.Scanner scanner) throws Exception {
		if (!scanner.getStatus()) {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
			HttpHeaders headers = prepareAuthHeader(scanner);
			headers.set("Content-Type", "application/json");
			HttpEntity<String> entity = new HttpEntity<>(headers);
			ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/v1/targets", HttpMethod.GET, entity, String.class);
			scanner.setStatus(true);
			scannerRepository.save(scanner);
			return response.getStatusCode() == HttpStatus.OK;
		} else
			throw new Exception("Scanner already initialized ");
	}
	//TODO Object mapping
	@Transactional
	public void createTarget(io.mixeway.db.entity.Scanner scanner, WebApp webApp) {
		try {
			if (scanner.getStatus()) {
				String createTargetBody = new Gson().toJson(new CreateTarget(webApp));
				RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
				HttpHeaders headers = prepareAuthHeader(scanner);
				headers.set("Content-Type", "application/json");
				HttpEntity<String> entity = new HttpEntity<>(createTargetBody,headers);
				ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/v1/targets", HttpMethod.POST, entity, String.class);
				if (response.getStatusCode() == HttpStatus.CREATED) {
					JSONObject responseObject = new JSONObject(Objects.requireNonNull(response.getBody()));
					webApp.setTargetId(responseObject.getString(Constants.ACUNETIX_TARGET_ID));
					webAppRepository.save(webApp);
				}
				else
					log.error("Failed target creation for {} with body of {}",webApp.getUrl(),createTargetBody);
			} else
				throw new Exception("Scanner Not initialized");
		} catch (HttpClientErrorException ex) {
			log.error("Error during creation of taget for acunetix, malformed request");
		} catch (PSQLException ex){
			log.error("PSQL Exception for webapp {}",webApp.getUrl());
		} catch (Exception dve){
			log.error("Exception occured during webapp update");

		}
	}
	//TODO Object mapping
	private void createLoginSequenceUrl(io.mixeway.db.entity.Scanner scanner, WebApp webApp) throws Exception {
		if (scanner.getStatus()) {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
			HttpHeaders headers = prepareAuthHeader(scanner);
			headers.set("Content-Type", "application/json");
			HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(new LoginSequenceUploadCreate(webApp)),headers);
			ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/v1/targets/"+webApp.getTargetId()+"/configuration/login_sequence", HttpMethod.POST, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				JSONObject responseObject = new JSONObject(Objects.requireNonNull(response.getBody()));
				webApp.setLoqinSequenceUploadUrl(responseObject.getString(Constants.ACUNETIX_UPLOAD_URL));
				webAppRepository.save(webApp);
			} else
				log.error("Failed upload url creation for {}",webApp.getUrl());
		} else
			throw new Exception("Scanner Not initialized");
	}
	//TODO Object mapping
	private void uploadLoginSequenceForTarget(io.mixeway.db.entity.Scanner scanner, WebApp webApp) throws Exception {
		if (scanner.getStatus()) {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
			HttpHeaders headers = prepareAuthHeader(scanner);
			headers.set("Content-Type", "application/octet-stream");
			headers.set("Content-Range", createContentRageHeader(webApp.getLoginSequence()));
			headers.set("Content-Disposition", "attachment; filename=\""+webApp.getLoginSequence().getName()+"\"");
			HttpEntity<String> entity = new HttpEntity<>(webApp.getLoginSequence().getLoginSequenceText(),headers);
			ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/v1/targets/"+webApp.getTargetId()+"/configuration/login_sequence", HttpMethod.POST, entity, String.class);
			if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
				updateTargetInfo(scanner,webApp);
			} else
				log.error("Failed upload url creation for {}",webApp.getUrl());
		} else
			throw new Exception("Scanner Not initialized");
	}
	//TODO Object mapping
	private void updateTargetInfo(io.mixeway.db.entity.Scanner scanner, WebApp webApp) throws Exception {
		if (scanner.getStatus()) {
			ResponseEntity<String> response = patchTarget(scanner, webApp, createJsonStringToUpdateTarget());
			if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
				webApp.setReadyToScan(true);
				webAppRepository.save(webApp);
			} else
				log.error("Failed configuring webapp {}",webApp.getUrl());
		} else
			throw new Exception("Scanner Not initialized");
	}

	private ResponseEntity<String> patchTarget(io.mixeway.db.entity.Scanner scanner, WebApp webApp, String jsonStringToUpdateTarget) throws Exception {
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
		HttpHeaders headers = prepareAuthHeader(scanner);
		headers.set("Content-Type", "application/json");
		HttpEntity<String> entity = new HttpEntity<>(jsonStringToUpdateTarget,headers);
		return restTemplate.exchange(scanner.getApiUrl() + "/api/v1/targets/"+webApp.getTargetId()+"/configuration", HttpMethod.PATCH, entity, String.class);
	}

	@Override
	@Transactional
	public void runScan(WebApp webApp, io.mixeway.db.entity.Scanner scanner) throws Exception {
		try {
			createTarget(scanner,webApp);
			if (webApp.getHeaders().size() > 0){
				createHeadersForTarget(scanner, webApp);
			}
			if (webApp.getWebAppCookies().size() > 0){
				createCookiesorTarget(scanner,webApp);
			}
			//TODO to routingDomian instead of PublicScan
			if (webApp.getPublicscan()){
				createProxyForWebApp(scanner,webApp);
			}
			if (scanner.getStatus()) {
				RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
				HttpHeaders headers = prepareAuthHeader(scanner);
				headers.set("Content-Type", "application/json");
				HttpEntity<String> entity = new HttpEntity<>(createJsonStringForRunScan(webApp), headers);
				ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/v1/scans", HttpMethod.POST, entity, String.class);
				if (response.getStatusCode() == HttpStatus.CREATED) {
					webApp.setRunning(true);
					webAppRepository.save(webApp);
					log.info("Scan started for {} -  {}", webApp.getProject().getName(), webApp.getUrl());
				} else
					log.error("Unable to start scan for {}", webApp.getUrl());
			} else
				throw new Exception("Scanner Not initialized");
		} catch (HttpClientErrorException ex){
			log.error("Response from acunetix /api/v1/scans {} for url {}", ex.getStatusCode(),webApp.getUrl());
		} catch (DataIntegrityViolationException dve){
			log.error("EXception occured during runScan");

		}
	}
	@Override
	public Boolean isScanDone(io.mixeway.db.entity.Scanner scanner, WebApp webApp) throws Exception {
		if (scanner.getStatus()) {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
			HttpHeaders headers = prepareAuthHeader(scanner);
			HttpEntity<String> entity = new HttpEntity<>(headers);
			ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/v1/targets/"+webApp.getTargetId(), HttpMethod.GET, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				JSONObject responseJson = new JSONObject(Objects.requireNonNull(response.getBody()));
				if ((responseJson.getString(Constants.ACUNETIX_TARGET_SCAN_STATUS)!=null) &&((responseJson.getString(Constants.ACUNETIX_TARGET_SCAN_STATUS).equals(Constants.ACUNETIX_TARGET_SCAN_STATUS_COMPLETED)) || (responseJson.getString(Constants.ACUNETIX_TARGET_SCAN_STATUS).equals(Constants.ACUNETIX_TARGET_SCAN_STATUS_FAILED)))) {
					webApp.setRunning(false);
					webApp.setLastExecuted(sdf.format(new Date()));
					webApp.setScanId(responseJson.getString(Constants.ACUNETIX_TARGET_SCAN_ID));
					webAppRepository.save(webApp);
					log.debug("Acunetix scan for {} ended status is {}", webApp.getUrl(),responseJson.getString(Constants.ACUNETIX_TARGET_SCAN_STATUS));
					return true;
				} else
					return false;
			} else {
				log.error("Unable to start target info for {}",webApp.getUrl());
				return false;
			}
		} else
			throw new Exception("Scanner Not initialized");
	}
	@Override
	public Boolean loadVulnerabilities(io.mixeway.db.entity.Scanner scanner, WebApp webApp, String paginator, List<WebAppVuln> oldVulns) throws Exception {
		if (scanner.getStatus()) {
			try {
				RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
				HttpHeaders headers = prepareAuthHeader(scanner);
				HttpEntity<String> entity = new HttpEntity<>(headers);
				String coursor = "";
				if (paginator != null)
					coursor = "&c=" + paginator;
				ResponseEntity<LoadVlnerabilitiesModel> response = restTemplate.exchange(scanner.getApiUrl() + "/api/v1/vulnerabilities?q=target_id:" + webApp.getTargetId() + coursor, HttpMethod.GET, entity, LoadVlnerabilitiesModel.class);
				if (response.getStatusCode() == HttpStatus.OK) {
					for (VulnerabilityModel vulnFromAcu : response.getBody().getVulnerabilities()){
						WebAppVuln vuln = new WebAppVuln();
						if (webApp.getCodeGroup() != null && webApp.getCodeProject() != null) {
							vuln.setCodeProject(webApp.getCodeProject());
						}
						vuln.setName(vulnFromAcu.getVt_name());
						vuln.setLocation(vulnFromAcu.getAffects_url());
						vuln.setSeverity(AcunetixSeverity.resolveSeverity(vulnFromAcu.getSeverity()));
						vuln.setWebApp(webApp);
						webAppVulnRepository.save(vuln);
						vuln = loadVulnDetails(vuln, scanner, vulnFromAcu.getVuln_id());
						WebAppVuln finalVuln = vuln;
						Optional<WebAppVuln> oldVulnExist = oldVulns.stream().filter(v -> v.getName().equals(finalVuln.getName()) && v.getSeverity().equals(finalVuln.getSeverity()) &&
								v.getLocation().equals(finalVuln.getLocation()) && v.getDescription().equals(finalVuln.getDescription())).findFirst();
						if (oldVulnExist.isPresent()) {
							vuln.setStatus(statusRepository.findByName(Constants.STATUS_EXISTING));
							vuln.setTicketId(oldVulnExist.get().getTicketId());
						} else {
							vuln.setStatus(statusRepository.findByName(Constants.STATUS_NEW));
							//TODO JIRA CREATION
							//jiraService.processRequest(webAppVulnRepository, Optional.of(vuln),webApp.getProject(),Constants.VULN_JIRA_WEBAPP,Constants.JIRA_AUTOCREATOR_LOG,false);
						}

					}
					if (response.getBody().getPagination().getNext_cursor() != null) {
						loadVulnerabilities(scanner, webApp,response.getBody().getPagination().getNext_cursor(), oldVulns);
					}
					log.info("WebApp Scan - Successfully loaded vulns for project {} - target {} ", webApp.getProject().getName(), webApp.getUrl());
					this.deleteTarget(scanner, webApp);
					webApp.setLastExecuted(sdf.format(new Date()));
					webAppRepository.save(webApp);
					return true;
				} else {
					log.error("Unable to load vulns info for {}", webApp.getUrl());
					return false;
				}
			} catch (HttpServerErrorException e) {
				log.error("Error trying to load vulnerabilities using url {} with msg {}","/api/v1/vulnerabilities?q=target_id:" + webApp.getTargetId(), e.getResponseBodyAsString());
				return false;
			}
		} else
			throw new Exception("Scanner Not initialized");
	}

	@Override
	public boolean canProcessRequest(io.mixeway.db.entity.Scanner scanner) {
		return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_ACUNETIX);
	}

	@Override
	public boolean canProcessRequest(ScannerType scannerType) {
		return scannerType.getName().equals(Constants.SCANNER_TYPE_ACUNETIX);
	}

	@Override
	public void saveScanner(ScannerModel scannerModel) throws Exception {
		io.mixeway.db.entity.Scanner acunetix= new io.mixeway.db.entity.Scanner();
		ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
		Proxies proxy = null;
		if (scannerModel.getProxy() != 0)
			proxy = proxiesRepository.getOne(scannerModel.getProxy());
		if(scannerModel.getRoutingDomain() == 0)
			throw new Exception("Null Domain");
		else
			acunetix.setRoutingDomain(routingDomainRepository.getOne(scannerModel.getRoutingDomain()));
		acunetix.setProxies(proxy);
		acunetix.setApiUrl(scannerModel.getApiUrl());
		acunetix.setApiKey(UUID.randomUUID().toString());
		acunetix.setStatus(false);
		acunetix.setScannerType(scannerType);
		// api key put to vault
		Map<String, String> apiKeyMap = new HashMap<>();
		apiKeyMap.put("password", scannerModel.getApiKey());
		operations.write("secret/"+acunetix.getApiKey(), apiKeyMap);
		scannerRepository.save(acunetix);
	}

	private WebAppVuln loadVulnDetails(WebAppVuln vuln, io.mixeway.db.entity.Scanner scanner, String vulnid) throws Exception {
		if (scanner.getStatus()) {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
			HttpHeaders headers = prepareAuthHeader(scanner);
			HttpEntity<String> entity = new HttpEntity<>(headers);
			ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/v1/vulnerabilities/"+vulnid, HttpMethod.GET, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				JSONObject vulnDesc = new JSONObject(Objects.requireNonNull(response.getBody()));
				if (vulnDesc.has(Constants.ACUNETIX_REQUEST)) {
					vuln.setDescription("Description: " + vulnDesc.getString(Constants.ACUNETIX_VULN_DESCRIPTION) + "\nImpact: " + vulnDesc.getString(Constants.ACUNETIX_IMPACT)
							+ "\nRequest: "+ vulnDesc.getString(Constants.ACUNETIX_REQUEST));
				} else {
					vuln.setDescription("Description: " + vulnDesc.getString(Constants.ACUNETIX_VULN_DESCRIPTION) + "\nImpact: " + vulnDesc.getString(Constants.ACUNETIX_IMPACT));
				}
				vuln.setRecommendation(vulnDesc.getString(Constants.ACUNETIX_VULN_RECOMMENDATION));
				vuln = webAppVulnRepository.save(vuln);
				return vuln;
			} else
				log.error("Unable to get vuln details info for {}",vulnid);
		} else
			throw new Exception("Scanner Not initialized");
		return vuln;
	}
	private void deleteTarget(io.mixeway.db.entity.Scanner scanner, WebApp webApp) throws Exception {
		if (scanner.getStatus()) {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
			HttpHeaders headers = prepareAuthHeader(scanner);
			HttpEntity<String> entity = new HttpEntity<>(headers);
			ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/v1/targets/"+webApp.getTargetId(), HttpMethod.DELETE, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				webApp.setReadyToScan(false);
				webApp.setRunning(false);
				webApp.setTargetId(null);
				webApp.setScanId(null);
				webAppRepository.save(webApp);
			} else
				log.error("Unable to delete target {}",webApp.getTargetId());
		} else
			throw new Exception("Scanner Not initialized");
	}
	private void createHeadersForTarget(io.mixeway.db.entity.Scanner scanner, WebApp webApp) throws Exception {
		try {
			if (scanner.getStatus()) {
				RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
				HttpHeaders headers = prepareAuthHeader(scanner);
				headers.set("Content-Type", "application/json");
				HttpEntity<String> entity = new HttpEntity<>(createHeadersJson(webApp), headers);
				ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/v1/targets/" + webApp.getTargetId() + "/configuration", HttpMethod.PATCH, entity, String.class);
				if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
					webApp.setReadyToScan(true);
				}
			} else
				throw new Exception("Scanner Not initialized");
		} catch (HttpClientErrorException ex){
			log.error("Response from acunetix /api/v1/targets/{}/configuration {} for url {}",webApp.getTargetId(), ex.getStatusCode(),webApp.getUrl());
		}
	}
	private void createCookiesorTarget(io.mixeway.db.entity.Scanner scanner, WebApp webApp) throws Exception {
		if (scanner.getStatus()) {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
			HttpHeaders headers = prepareAuthHeader(scanner);
			headers.set("Content-Type", "application/json");
			HttpEntity<String> entity = new HttpEntity<>(createCookiesJson(webApp),headers);
			try {
				ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/v1/targets/" + webApp.getTargetId() + "/configuration", HttpMethod.PATCH, entity, String.class);

				if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
					webApp.setReadyToScan(true);
				}
			} catch (HttpClientErrorException asd){
				log.info("body is: {}",asd.getResponseBodyAsString());
			}
		} else
			throw new Exception("Scanner Not initialized");
	}
	private String createHeadersJson(WebApp webApp) throws JsonProcessingException {
		Headers h = new Headers(webApp);
		ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
		return ow.writeValueAsString(h);
	}
	private String createCookiesJson(WebApp webApp) throws JsonProcessingException {
		Cookies c = new Cookies(webApp);
		ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
		return ow.writeValueAsString(c);
	}
	private void createProxyForWebApp(io.mixeway.db.entity.Scanner scanner, WebApp webApp) throws Exception {
		try {
			if (scanner.getStatus()) {
				ResponseEntity<String> response = patchTarget(scanner, webApp, createJsonStringForProxySet(scanner));
				if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
					webApp.setReadyToScan(true);
				}
			} else
				throw new Exception("Scanner Not initialized");
		} catch (HttpClientErrorException ex){
			log.error("Response from acunetix /targets/{}/configuration {} for url {}", webApp.getTargetId() ,ex.getStatusCode(),webApp.getUrl());
		}
	}
	private String createJsonStringForRunScan(WebApp webApp) throws JsonProcessingException {
		Schedule s = new Schedule();
		s.setDisable(false);
		s.setStart_date(null);
		s.setTime_sensitive(false);
		RunScan rs = new RunScan();
		rs.setProfile_id("11111111-1111-1111-1111-111111111111");
		rs.setTarget_id(webApp.getTargetId());
		rs.setSchedule(s);
		ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
		return ow.writeValueAsString(rs);
	}
	private String createJsonStringForProxySet(Scanner scanner) throws NumberFormatException, JSONException {
		JSONObject proxyValue = new JSONObject();
		proxyValue.append(Constants.ACUNETIX_PROXY_ENABLED, true);
		proxyValue.append(Constants.ACUNETIX_PROXY_ADDRESS, scanner.getProxies().getIp());
		proxyValue.append(Constants.ACUNETIX_PROXYPROTOCOL, "http");
		proxyValue.append(Constants.ACUNETIX_PROXY_PORT, Integer.parseInt(scanner.getProxies().getPort()));
		JSONObject proxy = new JSONObject();
		proxy.append(Constants.ACUNETIX_PROXY, proxyValue);
		return proxy.toString().replace("[", "").replaceAll("]", "");
	}
	private String createJsonStringToUpdateTarget() throws JSONException {
		JSONObject kind = new JSONObject();
		kind.append(Constants.ACUNETIX_CONFIGURE_KIND, Constants.ACUNETIX_CONFIGURE_KIND_LOGIN);
		JSONObject login = new JSONObject();
		login.append(Constants.ACUNETIX_CONFIGURE_LOGIN, kind);
		return login.toString();
	}
	private String createContentRageHeader(LoginSequence loginSequence) {
		return "bytes 0-"+(loginSequence.getLoginSequenceText().length()-1)+"/"+loginSequence.getLoginSequenceText().length();
	}

}
