package io.mixeway.scanmanager.integrations.acunetix.apiclient;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.gson.Gson;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.acunetix.model.AcunetixSeverity;
import io.mixeway.scanmanager.model.*;
import io.mixeway.scanmanager.service.SecurityScanner;
import io.mixeway.scanmanager.service.webapp.WebAppScanClient;
import io.mixeway.utils.ScannerModel;
import io.mixeway.utils.SecureRestTemplate;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.postgresql.util.PSQLException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.text.SimpleDateFormat;
import java.util.*;


@Service
@Log4j2
@RequiredArgsConstructor
public class AcunetixApiClient implements WebAppScanClient, SecurityScanner {
	private final VaultHelper vaultHelper;
	private final WebAppRepository webAppRepository;
	private final SecureRestTemplate secureRestTemplate;
	private final StatusRepository statusRepository;
	private final RoutingDomainRepository routingDomainRepository;
	private final ScannerRepository scannerRepository;
	private final ScannerTypeRepository scannerTypeRepository;
	private final ProxiesRepository proxiesRepository;
	private final VulnTemplate vulnTemplate;
	
	private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	
	private HttpHeaders prepareAuthHeader(Scanner scanner) throws Exception {
		if (scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_ACUNETIX)) {
			HttpHeaders headers = new HttpHeaders();
			headers.set("X-Auth", vaultHelper.getPassword(scanner.getApiKey()));
			return headers;
		} else
			throw new Exception("Trying to prepare auth for non acunetix scanner. Somtheing went wrong..");
	}
	@Override
	@Transactional(propagation = Propagation.REQUIRES_NEW)
	public void configureWebApp(WebApp webApp, Scanner scanner) throws Exception   {
			if ( !webApp.getRunning()) {
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
			} else
				log.debug("WebApp rest api scan omitting.. {}", webApp.getUrl());
	}
	//TODO Object mapping
	@Override
	public boolean initialize(Scanner scanner) throws Exception {
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
	public void createTarget(Scanner scanner, WebApp webApp) {
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
			log.error("Error during creation of taget for acunetix, malformed request - {} - {}", ex.getStatusCode(),ex.getResponseBodyAsString());
		} catch (PSQLException ex){
			log.error("PSQL Exception for webapp {}",webApp.getUrl());
		} catch (Exception dve){
			log.error("Exception occured during webapp update");

		}
	}
	//TODO Object mapping
	private void createLoginSequenceUrl(Scanner scanner, WebApp webApp) throws Exception {
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
	private void uploadLoginSequenceForTarget(Scanner scanner, WebApp webApp) throws Exception {
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
	private void updateTargetInfo(Scanner scanner, WebApp webApp) throws Exception {
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

	private ResponseEntity<String> patchTarget(Scanner scanner, WebApp webApp, String jsonStringToUpdateTarget) throws Exception {
		try {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
			HttpHeaders headers = prepareAuthHeader(scanner);
			headers.set("Content-Type", "application/json");
			HttpEntity<String> entity = new HttpEntity<>(jsonStringToUpdateTarget, headers);
			return restTemplate.exchange(scanner.getApiUrl() + "/api/v1/targets/" + webApp.getTargetId() + "/configuration", HttpMethod.PATCH, entity, String.class);
		} catch (ResourceAccessException e) {
			log.error("Unable to Patch target for scanner - resource not avaliable {}", scanner.getApiUrl());
		}
		return null;
	}

	@Override
	@Transactional
	public void runScan(WebApp webApp, Scanner scanner) throws Exception {
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
		} catch (ResourceAccessException e){
			log.error("Resource not avaliable {}", scanner.getApiUrl());
		}
	}
	@Override
	public Boolean isScanDone(Scanner scanner, WebApp webApp) throws Exception {
		if (scanner.getStatus()) {
			RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
			HttpHeaders headers = prepareAuthHeader(scanner);
			HttpEntity<String> entity = new HttpEntity<>(headers);
			ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/v1/targets/"+webApp.getTargetId(), HttpMethod.GET, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				JSONObject responseJson = new JSONObject(Objects.requireNonNull(response.getBody()));
				if ((responseJson.getString(Constants.ACUNETIX_TARGET_SCAN_STATUS)!=null) && ((responseJson.getString(Constants.ACUNETIX_TARGET_SCAN_STATUS).equals(Constants.ACUNETIX_TARGET_SCAN_STATUS_COMPLETED)) ||
						responseJson.getString(Constants.ACUNETIX_TARGET_SCAN_STATUS).equals(Constants.ACUNETIX_TARGET_SCAN_STATUS_FAILED) ||
								responseJson.getString(Constants.ACUNETIX_TARGET_SCAN_STATUS).equals(Constants.ACUNETIX_TARGET_SCAN_STATUS_ABORTED))) {
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
	public Boolean loadVulnerabilities(Scanner scanner, WebApp webApp, String paginator, List<ProjectVulnerability> oldVulns) throws Exception {
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
					List<ProjectVulnerability> vulnsToPersist = new ArrayList<>();
					for (VulnerabilityModel vulnFromAcu : response.getBody().getVulnerabilities()){
						Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerabilityWithRecommendationAndReferences(vulnFromAcu.getVt_name(),vulnFromAcu.getRecommendation(),prepareRefs(vulnFromAcu.getReferences()));
						ProjectVulnerability vuln = new ProjectVulnerability(webApp,null,vulnerability,null,
								null, AcunetixSeverity.resolveSeverity(vulnFromAcu.getSeverity()),null,vulnFromAcu.getAffects_url(),
								null,vulnTemplate.SOURCE_WEBAPP,null, null);
						if (webApp.getCodeProject() != null) {
							vuln.setCodeProject(webApp.getCodeProject());
						}
						vuln = loadVulnDetails(vuln, scanner, vulnFromAcu.getVuln_id());
						vuln.updateStatusAndGrade(oldVulns,vulnTemplate);
						vulnsToPersist.add((vuln));
						//vulnTemplate.vulnerabilityPersist(oldVulns, vuln);
						//vulnTemplate.projectVulnerabilityRepository.save(vuln);
						//TODO JIRA CREATION

					}
					vulnTemplate.vulnerabilityPersistList(oldVulns,vulnsToPersist);
					if (response.getBody().getPagination().getNext_cursor() != null) {
						loadVulnerabilities(scanner, webApp,response.getBody().getPagination().getNext_cursor(), oldVulns);
					}
					log.info("WebApp Scan - Successfully loaded vulns for project {} - target {} ", webApp.getProject().getName(), webApp.getUrl());
					this.deleteTarget(scanner, webApp);
					webApp.setLastExecuted(sdf.format(new Date()));
					webApp.setRequestId(null);
					webApp.setScanId(null);
					webAppRepository.save(webApp);
					return true;
				} else {
					log.error("Unable to load vulns info for {}", webApp.getUrl());
					this.deleteTarget(scanner, webApp);
					return false;
				}
			} catch (HttpServerErrorException e) {
				log.error("Error trying to load vulnerabilities using url {} with - {} - {}","/api/v1/vulnerabilities?q=target_id:" + webApp.getTargetId(), e.getStatusCode(), e.getResponseBodyAsString());
				this.deleteTarget(scanner, webApp);
				return false;
			}
		} else
			throw new Exception("Scanner Not initialized");
	}

	private String prepareRefs(List<Reference> references) {
		int i = 1;
		String refs = "";
		if (references != null) {
			for (Reference ref : references) {
				refs += "[" + i + "] " + ref.getHref() + "\n";
			}
		}
		return refs;
	}

	@Override
	public boolean canProcessRequest(Scanner scanner) {
		return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_ACUNETIX) && scanner.getStatus();
	}

	@Override
	public boolean canProcessInitRequest(Scanner scanner) {
		return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_ACUNETIX);
	}

	@Override
	public boolean canProcessRequest(ScannerType scannerType) {
		return scannerType.getName().equals(Constants.SCANNER_TYPE_ACUNETIX);
	}

	@Override
	public Scanner saveScanner(ScannerModel scannerModel) throws Exception {
		Scanner acunetix= new Scanner();
		ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
		Proxies proxy = null;
		if (scannerModel.getProxy() != 0)
			proxy = proxiesRepository.getOne(scannerModel.getProxy());
		if(scannerModel.getRoutingDomain() != 0)
			acunetix.setRoutingDomain(routingDomainRepository.getOne(scannerModel.getRoutingDomain()));
		acunetix.setProxies(proxy);
		acunetix.setApiUrl(scannerModel.getApiUrl());
		acunetix.setStatus(false);
		acunetix.setScannerType(scannerType);
		// api key put to vault
		String uuidToken = UUID.randomUUID().toString();
		if (vaultHelper.savePassword(scannerModel.getApiKey(), uuidToken )) {
			acunetix.setApiKey(uuidToken);
		} else {
			acunetix.setApiKey(scannerModel.getApiKey());
		}
		return scannerRepository.save(acunetix);
	}

	private ProjectVulnerability loadVulnDetails(ProjectVulnerability vuln, Scanner scanner, String vulnid) throws Exception {
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
				return vuln;
			} else
				log.error("Unable to get vuln details info for {}",vulnid);
		} else
			throw new Exception("Scanner Not initialized");
		return vuln;
	}
	private void deleteTarget(Scanner scanner, WebApp webApp) throws Exception {
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
	private void createHeadersForTarget(Scanner scanner, WebApp webApp) throws Exception {
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
		} catch (ResourceAccessException ex){
			log.error("Host of scanner is not avaliable {}",scanner.getApiUrl());
		}
	}
	private void createCookiesorTarget(Scanner scanner, WebApp webApp) throws Exception {
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
	private void createProxyForWebApp(Scanner scanner, WebApp webApp) throws Exception {
		try {
			if (scanner.getStatus()) {
				ResponseEntity<String> response = patchTarget(scanner, webApp, createJsonStringForProxySet(scanner));
				if (response != null && response.getStatusCode() == HttpStatus.NO_CONTENT) {
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
