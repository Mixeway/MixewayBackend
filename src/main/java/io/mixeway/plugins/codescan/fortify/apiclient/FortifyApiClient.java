package io.mixeway.plugins.codescan.fortify.apiclient;

import com.google.gson.JsonObject;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.codescan.fortify.model.FileContentDataModel;
import io.mixeway.plugins.codescan.fortify.model.IssueDetailDataModel;
import io.mixeway.plugins.codescan.model.SSCRequestHelper;
import io.mixeway.plugins.codescan.service.CodeScanClient;
import io.mixeway.pojo.*;
import io.mixeway.rest.model.ScannerModel;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponseSupport;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.ProtocolException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class FortifyApiClient implements CodeScanClient, SecurityScanner {
	private static final Logger log = LoggerFactory.getLogger(FortifyApiClient.class);
	private VaultOperations operations;
	private ScannerRepository scannerRepository;
	private CodeVulnRepository codeVulnRepository;
	private CodeProjectRepository codeProjectRepository;
	private CodeGroupRepository codeGroupRepository;
	private FortifySingleAppRepository fortifySingleAppRepository;
	private StatusRepository statusRepository;
	private SecureRestTemplate secureRestTemplate;
	private ScannerTypeRepository scannerTypeRepository;
	private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
	private SimpleDateFormat sdfForFortify = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

	@Autowired
	FortifyApiClient(VaultOperations operations, ScannerRepository scannerRepository, CodeVulnRepository codeVulnRepository,
					 CodeProjectRepository codeProjectRepository, CodeGroupRepository codeGroupRepository, FortifySingleAppRepository fortifySingleAppRepository,
					 StatusRepository statusRepository, SecureRestTemplate secureRestTemplate, ScannerTypeRepository scannerTypeRepository){
		this.operations = operations;
		this.scannerRepository = scannerRepository;
		this.codeVulnRepository = codeVulnRepository;
		this.codeProjectRepository = codeProjectRepository;
		this.codeGroupRepository = codeGroupRepository;
		this.fortifySingleAppRepository = fortifySingleAppRepository;
		this.statusRepository = statusRepository;
		this.secureRestTemplate = secureRestTemplate;
		this.scannerTypeRepository = scannerTypeRepository;
	}

	private JsonObject unifiedTokenObject = new JsonObject();
	private FortifyTokenValidator fortifyTokenValidator = new FortifyTokenValidator();

	//SSC Generation
	@Override
	public boolean initialize(io.mixeway.db.entity.Scanner scanner) throws JSONException, ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		if (scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_FORTIFY)) {
			return generateToken(scanner);
		} else if (scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_FORTIFY_SCA)){
			try {
				RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
				ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl()+"/initialize", HttpMethod.GET, null, String.class);
				if (response.getStatusCode().equals(HttpStatus.OK)) {
					scanner.setStatus(true);
					scannerRepository.save(scanner);
					return true;
				}
			} catch (ProtocolException e) {
				log.error("Exception occured during initialization of scanner: '{}'",e.getMessage());
			}
			return false;
		} else {
			return false;
		}
	}
	private boolean generateToken(io.mixeway.db.entity.Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
		unifiedTokenObject.addProperty("type", "UnifiedLoginToken");
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
		VaultResponseSupport<Map<String, Object>> password = operations.read("secret/" + scanner.getPassword());
		assert password != null;
		final String passwordToEncode = scanner.getUsername() + ":" + Objects.requireNonNull(password.getData()).get("password").toString();
		final byte[] passwordToEncodeBytes = passwordToEncode.getBytes(StandardCharsets.UTF_8);
		HttpHeaders headers = new HttpHeaders();
		headers.set("Content-Type", "application/json");
		headers.set("Authorization", "Basic " + Base64.getEncoder().encodeToString(passwordToEncodeBytes));
		HttpEntity<String> entity = new HttpEntity<>(unifiedTokenObject.toString(), headers);
		String API_GET_TOKEN = "/api/v1/tokens";
		ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + API_GET_TOKEN, HttpMethod.POST, entity, String.class);
		if (response.getStatusCode() == HttpStatus.CREATED) {
			JSONObject responseJson = new JSONObject(Objects.requireNonNull(response.getBody()));
			scanner.setFortifytoken(responseJson.getJSONObject("data").getString("token"));
			String date = responseJson.getJSONObject("data").getString("terminalDate");
			Date expiration = sdfForFortify.parse(date);
			scanner.setFortifytokenexpiration(sdf.format(expiration));
			if(!scanner.getStatus()){
				scanner.setStatus(true);
			}
			scannerRepository.save(scanner);
			return true;
		} else {
			log.error("Fortify Authorization failure");
			return false;
		}
	}

	//SSC Loading Vulnerabilities
	@Override
	public void loadVulnerabilities(io.mixeway.db.entity.Scanner scanner, CodeGroup codeGroup, String urlToGetNext, Boolean single, CodeProject codeProject, List<CodeVuln> codeVulns) throws ParseException, JSONException {
		try {
			SSCRequestHelper sscRequestHelper = prepareRestTemplate(scanner);
			String url;
			String API_DOWNLOAD_ISSUES = "/api/v1/projectVersions/versionid/issues?qm=issues&q=[fortify+priority+order]:high+OR+[fortify+priority+order]:critical";
			if (single) {
				url = scanner.getApiUrl() + API_DOWNLOAD_ISSUES.replace("versionid",
						String.valueOf(codeGroup.getVersionIdsingle()>0?codeGroup.getVersionIdsingle():codeGroup.getVersionIdAll()));
			} else {
				url = scanner.getApiUrl() + API_DOWNLOAD_ISSUES.replace("versionid",
						String.valueOf(codeGroup.getVersionIdAll()));
			}
			if (urlToGetNext != null)
				url = url+"&"+urlToGetNext.split("&")[2];
			ResponseEntity<String> response = sscRequestHelper
					.getRestTemplate()
					.exchange(url, HttpMethod.GET, sscRequestHelper.getHttpEntity(), String.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				JSONObject responseJson = new JSONObject(Objects.requireNonNull(response.getBody()));
				saveVulnerabilities(codeGroup, responseJson.getJSONArray(Constants.VULNERABILITIES_LIST),codeProject,scanner);
				if (responseJson.getJSONObject(Constants.FORTIFY_LINKS).has(Constants.FORTIFY_LINKS_NEXT)){
					this.loadVulnerabilities(scanner,codeGroup,responseJson.getJSONObject(Constants.FORTIFY_LINKS)
							.getJSONObject(Constants.FORTIFY_LINKS_NEXT).getString(Constants.FORTIFY_LINKS_NEXT_HREF),single,codeProject,codeVulns);
				}
				log.debug("FortifyApiClient- loaded {} vulns for {}", responseJson.getJSONArray(Constants.VULNERABILITIES_LIST).length(), codeGroup.getName());
			} else {
				log.error("Fortify Authorization failure");
			}
			if (codeVulns !=null) {
				log.debug("Contains old vulns, reimporting");
				reimportAnalysisFromScans(codeProject,codeGroup, codeVulns);
			}
		} catch (HttpClientErrorException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException | URISyntaxException hcee){
			log.error("FortifySSC HttpClientErrorExceptio was unsuccessfull with code of: {} {} ",hcee.getLocalizedMessage(),hcee.getMessage());
		}
	}

	//For single project reimporting analysis
	private void reimportAnalysisFromScans(CodeProject codeProject, CodeGroup codeGroup, List<CodeVuln> oldVulns) {
		List<CodeVuln> codeVulns = new ArrayList<>();
		if (codeProject !=null ) {
			codeVulns = codeVulnRepository.findByCodeProject(codeProject);
		} else if (codeGroup!=null) {
			codeVulns = codeVulnRepository.findByCodeGroup(codeGroup);
		}
		for (CodeVuln cv : codeVulns){
			try {
				Optional<CodeVuln> x = oldVulns.stream().filter(c -> c.getExternalId().equals(cv.getExternalId())).findFirst();
				if (x.isPresent()) {
					cv.setAnalysis(x.get().getAnalysis());
					cv.setTicketId(x.get().getTicketId());
					cv.setStatus(statusRepository.findByName(Constants.STATUS_EXISTING));
				} else {
					cv.setStatus(statusRepository.findByName(Constants.STATUS_NEW));
					//TODO AUto Jira creation
				}
				codeVulnRepository.save(cv);
			} catch (NullPointerException ignored) {}
		}
	}


	private void saveVulnerabilities(CodeGroup codeGroup, JSONArray jsonArray, CodeProject cp, io.mixeway.db.entity.Scanner scanner) throws JSONException, CertificateException, ParseException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, IOException, URISyntaxException {
		for (int i = 0; i < jsonArray.length(); i++) {
			JSONObject vulnJson = jsonArray.getJSONObject(i);
			CodeVuln vuln = new CodeVuln();
			vuln.setAnalysis(vulnJson.getString(Constants.VULN_ANALYSIS));
			vuln.setSeverity(vulnJson.getString(Constants.VULN_CRITICALITY));
			vuln.setName(vulnJson.getString(Constants.VULN_NAME));
			vuln.setInserted(sdf.format(new Date()));
			vuln.setFilePath(vulnJson.getString(Constants.VULN_PATH)+":"+vulnJson.getString(Constants.FORTIFY_LINE_NUMVER));
			vuln = createDescriptionAndState(vulnJson.getString(Constants.VULN_ISSUE_INSTANCE_ID),vulnJson.getLong(Constants.VULN_ISSUE_ID),
					codeGroup.getVersionIdAll(), scanner, vuln);
			if(codeGroup.getHasProjects() && cp == null && codeGroup.getProjects().size()>1) {
				CodeProject codeProject = getProjectFromPath(codeGroup,vulnJson.getString(Constants.VULN_PATH));
				vuln.setCodeProject(codeProject);
				vuln.setCodeGroup(codeGroup);
			}else if (codeGroup.getHasProjects() && cp != null){
				vuln.setCodeProject(cp);
				vuln.setCodeGroup(codeGroup);
			}else
				vuln.setCodeGroup(codeGroup);
			codeVulnRepository.save(vuln);
		}

	}

	private CodeVuln createDescriptionAndState(String instanceId, Long id, int versionid, io.mixeway.db.entity.Scanner scanner, CodeVuln codeVuln) throws ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, IOException, URISyntaxException {
		StringBuilder issueDetails = new StringBuilder();
		codeVuln.setExternalId((id));
		SSCRequestHelper sscRequestHelper = prepareRestTemplate(scanner);
		ResponseEntity<IssueDetailDataModel> response = sscRequestHelper
				.getRestTemplate()
				.exchange(scanner.getApiUrl()+"/api/v1/issueDetails/"+id, HttpMethod.GET, sscRequestHelper.getHttpEntity(), IssueDetailDataModel.class);
		if (response.getStatusCode() == HttpStatus.OK) {
			issueDetails.append("Severity: ")
					.append(codeVuln.getSeverity());
			issueDetails.append("\n");
			issueDetails.append("\n");
			issueDetails.append("Full details: " + "https://fortifyssc.corpnet.pl/ssc/html/ssc/version/"+versionid+"/fix/"+id+"/?engineType=SCA&issue="+instanceId+"&filterSet=a243b195-0a59-3f8b-1403-d55b7a7d78e6");
			issueDetails.append("\n");
			issueDetails.append("Full filename: ")
					.append(Objects.requireNonNull(response.getBody()).getIssueDetailModel().getFullFileName())
					.append(":").append(response.getBody().getIssueDetailModel().getLineNumber());
			issueDetails.append("\n");
			issueDetails.append("Details: ")
					.append(response.getBody().getIssueDetailModel().getDetail());
			issueDetails.append("\n");
			issueDetails.append("CodeSnippet:\n ")
					.append(getCodeSnippet(scanner, versionid, response.getBody().getIssueDetailModel().getFullFileName(),
					response.getBody().getIssueDetailModel().getLineNumber()));
			codeVuln.setDescription(issueDetails.toString());
			codeVuln.setFilePath(response.getBody().getIssueDetailModel().getFullFileName()+":"+response.getBody().getIssueDetailModel().getLineNumber());
			if (response.getBody().getIssueDetailModel().getScanStatus().equals(Constants.FORTIFY_ISSUE_STATE_UPDATED)){
				codeVuln.setStatus(statusRepository.findByName(Constants.STATUS_EXISTING));
			} else {
				codeVuln.setStatus(statusRepository.findByName(Constants.STATUS_NEW));
				//TODO Auto jira generation
			}
		}

		return codeVuln;
	}

	private String getCodeSnippet(io.mixeway.db.entity.Scanner scanner, int versionid, String fullFileName, int lineNumber) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
		String codeSnippet = "";
		SSCRequestHelper sscRequestHelper = prepareRestTemplate(scanner);
		ResponseEntity<FileContentDataModel> response = sscRequestHelper
				.getRestTemplate()
				.exchange(scanner.getApiUrl()+"/api/v1/projectVersions/"+versionid+"/sourceFiles?q=path:\""
				+fullFileName+"\"", HttpMethod.GET, sscRequestHelper.getHttpEntity(), FileContentDataModel.class);
		if (response.getStatusCode() == HttpStatus.OK) {
			List<String> lines = new BufferedReader(new StringReader(Objects.requireNonNull(response.getBody()).getFileContentModel().get(0).getFileContent()))
					.lines()
					.collect(Collectors.toList());

			codeSnippet = lines.stream().skip(lineNumber).limit(10).collect(Collectors.joining("\n"));
		}
		return codeSnippet;
	}

	private CodeProject getProjectFromPath(CodeGroup group, String string) {
		String projectName = string.split("/")[0];
		Optional<CodeProject> codeProject = codeProjectRepository.findByCodeGroupAndName(group, projectName);
		if(codeProject.isPresent())
			return codeProject.get();
		else {
			CodeProject codeProjectNew = new CodeProject();
			codeProjectNew.setCodeGroup(group);
			codeProjectNew.setSkipAllScan(true);
			codeProjectNew.setName(projectName);
			codeProjectRepository.save(codeProjectNew);
			log.info("Creating project {} for group {}", projectName,group.getName());
			return codeProjectNew;
		}
	}
	//SSC - status of cloduscan job
	private boolean verifyCloudScanJob(CodeGroup cg, FortifySingleApp fortifySingleApp) throws ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, IOException {
		try {
			io.mixeway.db.entity.Scanner scanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY)).get(0);
			SSCRequestHelper sscRequestHelper = prepareRestTemplate(scanner);
			String API_JOB_STATE = "/api/v1/cloudjobs";
			ResponseEntity<CloudJobState> response = sscRequestHelper
					.getRestTemplate()
					.exchange(scanner.getApiUrl() + API_JOB_STATE + "/" + (fortifySingleApp == null ? cg.getScanid() : fortifySingleApp.getJobToken()), HttpMethod.GET, sscRequestHelper.getHttpEntity(), CloudJobState.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				if (Objects.requireNonNull(response.getBody()).getData().getJobState().equals("UPLOAD_COMPLETED")) {
					codeGroupRepository.save(cg);
					if (fortifySingleApp != null) {
						fortifySingleApp.setFinished(true);
						fortifySingleAppRepository.save(fortifySingleApp);
					}
					log.info("CloudScan ended for {}", cg.getName());
					return true;
				}
			}
			return false;
		} catch (HttpClientErrorException ex){
			log.debug("HttpClientErrorException during cloud scan job verification for {}",cg.getScanid());
		}
		return false;
	}
	private SSCRequestHelper prepareRestTemplate(io.mixeway.db.entity.Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
		Date fortifyTokenExpirationDate = sdf.parse(scanner.getFortifytokenexpiration()+".123");
		LocalDateTime fortifyTokenExpiration = LocalDateTime.ofInstant(fortifyTokenExpirationDate.toInstant(), ZoneId.systemDefault());
		if (fortifyTokenValidator.isTokenValid(scanner.getFortifytoken(), fortifyTokenExpiration)) {
			generateToken(scanner);
		}
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
		HttpHeaders headers = new HttpHeaders();
		headers.set(Constants.HEADER_AUTHORIZATION, Constants.FORTIFY_TOKEN + " " + scanner.getFortifytoken());
		HttpEntity entity = new HttpEntity(headers);

		return new SSCRequestHelper(restTemplate,entity);
	}

	private CreateFortifyScanRequest prepareScanRequestForGroup(CodeGroup cg){
		List<io.mixeway.db.entity.Scanner> fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY_SCA));
		CreateFortifyScanRequest fortifyScanRequest = new CreateFortifyScanRequest();
		VaultResponseSupport<Map<String,Object>> token = operations.read("secret/"+fortify.get(0).getFortifytoken());
		assert token != null;
		fortifyScanRequest.setCloudCtrlToken(Objects.requireNonNull(token.getData()).get("password").toString());
		fortifyScanRequest.setGroupName(cg.getName());
		fortifyScanRequest.setUsername(cg.getRepoUsername());
		fortifyScanRequest.setSingle(false);
		VaultResponseSupport<Map<String,Object>> password = operations.read("secret/"+cg.getRepoPassword());
		assert password != null;
		fortifyScanRequest.setPassword( Objects.requireNonNull(password.getData()).get("password").toString());
		fortifyScanRequest.setVersionId(cg.getVersionIdAll());
		fortifyScanRequest.setProjects(prepareProjectCodeForGroup(cg));
		return fortifyScanRequest;
	}
	private List<ProjectCode> prepareProjectCodeForGroup(CodeGroup cg){
		List<ProjectCode> projectCodes = new ArrayList<>();
		for (CodeProject cp : cg.getProjects()){
			if (!cp.getSkipAllScan()) {
				ProjectCode pc = new ProjectCode();
				pc.setProjectName(cp.getName());
				pc.setBranch(cp.getBranch()!=null && !cp.getBranch().equals("") ? cp.getBranch() : Constants.CODE_DEFAULT_BRANCH);
				pc.setProjectRepoUrl(cp.getRepoUrl());
				pc.setTechnique(cp.getTechnique());
				pc.setParams(cp.getAdditionalPath());
				projectCodes.add(pc);
			}
		}
		return projectCodes;
	}
	private CreateFortifyScanRequest prepareScanRequestForProject(CodeProject cp){
		List<io.mixeway.db.entity.Scanner> fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY_SCA));
		if (fortify.size()>0) {
			CreateFortifyScanRequest fortifyScanRequest = new CreateFortifyScanRequest();
			VaultResponseSupport<Map<String, Object>> token = operations.read("secret/" + fortify.get(0).getFortifytoken());
			assert token != null;
			fortifyScanRequest.setCloudCtrlToken(Objects.requireNonNull(token.getData()).get("password").toString());
			fortifyScanRequest.setGroupName(cp.getCodeGroup().getName());
			fortifyScanRequest.setSingle(true);
			fortifyScanRequest.setUsername(cp.getCodeGroup().getRepoUsername());
			VaultResponseSupport<Map<String, Object>> password = operations.read("secret/" + cp.getCodeGroup().getRepoPassword());
			assert password != null;
			fortifyScanRequest.setPassword(Objects.requireNonNull(password.getData()).get("password").toString());
			fortifyScanRequest.setVersionId(cp.getCodeGroup().getVersionIdsingle()>0 ? cp.getCodeGroup().getVersionIdsingle() : cp.getCodeGroup().getVersionIdAll() );
			ProjectCode pc = new ProjectCode();
			pc.setTechnique(cp.getTechnique());
			pc.setBranch(cp.getBranch() != null && !cp.getBranch().equals("") ? cp.getBranch() : Constants.CODE_DEFAULT_BRANCH);
			pc.setProjectRepoUrl(cp.getRepoUrl());
			pc.setProjectName(cp.getName());
			fortifyScanRequest.setProjects(Collections.singletonList(pc));
			return fortifyScanRequest;
		} else
			return null;
	}
	@Override
	public boolean isScanDone(CodeGroup cg) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, ParseException, JSONException {
		if (cg.isRunning() && cg.getRequestid()!=null && cg.getScanid()==null){
			getScanId(cg);
			return false;
		} else if (cg.isRunning() && cg.getScanid() !=null && cg.getRequestid() != null) {
			if (cg.getScope().equals(Constants.FORTIFY_SCOPE_ALL)){
				return verifyCloudScanJob(cg,null);
			} else {
				List<FortifySingleApp> apps = fortifySingleAppRepository.findByFinishedAndDownloaded(true,false);
				for (FortifySingleApp app : apps){
					boolean tets = verifyCloudScanJob(app.getCodeGroup(), app);
					return tets;
				}
			}
		} else {
			log.warn("Setrange thing happend for {} - running: {}, requestId: {}, scanId: {}", cg.getName(),cg.isRunning(),cg.getRequestid(),cg.getScanid());
		}
		return false;
	}

	@Override
	public boolean canProcessRequest(CodeGroup cg) {
		Optional<io.mixeway.db.entity.Scanner> fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY_SCA)).stream().findFirst();
		return fortify.isPresent();
	}

	@Override
	public boolean canProcessRequest(io.mixeway.db.entity.Scanner scanner) {
		return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_FORTIFY_SCA) || scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_FORTIFY);
	}

	@Override
	public boolean canProcessRequest(ScannerType scannerType) {
		return scannerType.getName().equals(Constants.SCANNER_TYPE_FORTIFY) || scannerType.getName().equals(Constants.SCANNER_TYPE_FORTIFY_SCA);
	}

	@Override
	public void saveScanner(ScannerModel scannerModel) {
		ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
		if (scannerType.getName().equals(Constants.SCANNER_TYPE_FORTIFY)){
			io.mixeway.db.entity.Scanner fortify = new io.mixeway.db.entity.Scanner();
			fortify.setApiUrl(scannerModel.getApiUrl());
			fortify.setPassword(UUID.randomUUID().toString());
			fortify.setUsername(scannerModel.getUsername());
			fortify.setStatus(false);
			fortify.setScannerType(scannerType);
			// api key put to vault
			Map<String, String> passwordKeyMap = new HashMap<>();
			passwordKeyMap.put("password", scannerModel.getPassword());
			operations.write("secret/" + fortify.getPassword(), passwordKeyMap);
			scannerRepository.save(fortify);
		} else if (scannerType.getName().equals(Constants.SCANNER_TYPE_FORTIFY_SCA)){
			io.mixeway.db.entity.Scanner fortify = new io.mixeway.db.entity.Scanner();
			fortify.setApiUrl(scannerModel.getApiUrl());
			fortify.setFortifytoken(UUID.randomUUID().toString());
			fortify.setStatus(false);
			fortify.setScannerType(scannerType);
			// api key put to vault
			Map<String, String> passwordKeyMap = new HashMap<>();
			passwordKeyMap.put("password", scannerModel.getCloudCtrlToken());
			operations.write("secret/" + fortify.getFortifytoken(), passwordKeyMap);
			scannerRepository.save(fortify);
		}
	}

	private void getScanId(CodeGroup cg) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		List<io.mixeway.db.entity.Scanner> fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY_SCA));
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
		ResponseEntity<FortifyScan> response = restTemplate.exchange(fortify.get(0).getApiUrl()+"/check/"+cg.getRequestid(), HttpMethod.GET, null, FortifyScan.class);
		if (response.getStatusCode().equals(HttpStatus.OK)) {
			if (Objects.requireNonNull(response.getBody()).getError() != null && response.getBody().getError()) {

				Optional<FortifySingleApp> fortifySingleApp = fortifySingleAppRepository.findByRequestId(response.getBody().getRequestId());
				if (fortifySingleApp.isPresent()) {
					fortifySingleApp.get().setFinished(true);
					fortifySingleApp.get().setDownloaded(true);
					fortifySingleAppRepository.save(fortifySingleApp.get());
				}
				cg.setRunning(false);
				codeGroupRepository.save(cg);
				log.warn("Fortify Scan error on {} with scope of {}", cg.getName(), cg.getScope());
			} else if (response.getBody().getScanId() != null && !response.getBody().getScanId().equals("")) {
				if (response.getBody().getProjectName() != null && !response.getBody().getProjectName().equals("")) {
					CodeProject cp = codeProjectRepository.findByCodeGroupAndName(cg, response.getBody().getProjectName()).get();
					cp.setCommitid(response.getBody().getCommitid());
					codeProjectRepository.save(cp);
					FortifySingleApp fortifySingleApp = new FortifySingleApp();
					fortifySingleApp.setCodeGroup(cg);
					fortifySingleApp.setCodeProject(cp);
					fortifySingleApp.setRequestId(response.getBody().getRequestId());
					fortifySingleApp.setJobToken(response.getBody().getScanId());
					fortifySingleApp.setFinished(false);
					fortifySingleApp.setDownloaded(false);
					fortifySingleAppRepository.save(fortifySingleApp);
					cp.setRunning(false);
					codeProjectRepository.save(cp);
					codeGroupRepository.save(cg);
					//verifycloudscan for single
				} else {
					cg.setScanid(response.getBody().getScanId());
					codeGroupRepository.save(cg);
					//verifycloudscan for group
				}
				log.info("Fortify scan was passed to cloudscan for [scope {}] {} ", cg.getScope(), cg.getName());
			}
		}
	}
	@Override
	public Boolean runScan(CodeGroup cg,CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		List<Scanner> fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY_SCA));
		if (codeGroupRepository.countByRunning(true) ==0 && fortify.size()>0) {
			if (!cg.isRunning()) {
				CreateFortifyScanRequest fortifyScanRequest;
				String scope;
				if (codeProject == null) {
					fortifyScanRequest = prepareScanRequestForGroup(cg);
					scope = Constants.FORTIFY_SCOPE_ALL;
				} else {
					fortifyScanRequest = prepareScanRequestForProject(codeProject);
					scope = codeProject.getName();
				}

				try {
					RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
					HttpHeaders headers = new HttpHeaders();
					headers.set("Content-Type", "application/json");
					HttpEntity<CreateFortifyScanRequest> entity = new HttpEntity<>(fortifyScanRequest, headers);
					ResponseEntity<FortifyScan> response = restTemplate.exchange(fortify.get(0).getApiUrl() + "/createscan", HttpMethod.PUT, entity, FortifyScan.class);
					if (response.getStatusCode().equals(HttpStatus.OK) && Objects.requireNonNull(response.getBody()).getRequestId() != null) {
						cg.setRequestid(response.getBody().getRequestId());
						cg.setRunning(true);
						cg.setScope(scope);
						codeGroupRepository.save(cg);
						if (codeProject!=null){
							codeProject.setRunning(true);
							codeProject.setRequestId(UUID.randomUUID().toString());
							codeProjectRepository.save(codeProject);
						}
						log.info("Fortify scan starged for [scope {}] {}",scope, cg.getName());
						return true;
					}
				} catch (ProtocolException e) {
					log.error("Exception occured during initialization of scanner: '{}'", e.getMessage());
				}
			} else {
				log.warn("Cannot start scan for {} because one is running with scope of {}", cg.getName(), cg.getScope());
			}
		} else {
			if (codeProject != null){
				log.info("There is already running scan [scope single] putting {} into queue[{}]", codeProject.getName(),cg.getName());
				codeProject.setInQueue(true);
				codeProjectRepository.save(codeProject);
			} else {
				log.info("There is already running scan [scope ALL], putting {} into queue", cg.getName());
				cg.setInQueue(true);
				codeGroupRepository.save(cg);
			}
		}
		return false;
	}
}