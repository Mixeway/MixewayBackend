package io.mixeway.integrations.codescan.plugin.fortify.apiclient;

import com.google.gson.JsonObject;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.integrations.opensourcescan.plugins.dependencytrack.apiclient.DependencyTrackApiClient;
import io.mixeway.integrations.bugtracker.BugTracking;
import io.mixeway.integrations.codescan.plugin.fortify.model.*;
import io.mixeway.integrations.codescan.model.TokenValidator;
import io.mixeway.integrations.codescan.model.CodeRequestHelper;
import io.mixeway.integrations.codescan.service.CodeScanClient;
import io.mixeway.pojo.*;
import io.mixeway.rest.model.ScannerModel;
import io.mixeway.rest.project.model.SASTProject;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
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
	private VaultHelper vaultHelper;
	private ScannerRepository scannerRepository;
	private CodeVulnRepository codeVulnRepository;
	private CodeProjectRepository codeProjectRepository;
	private CodeGroupRepository codeGroupRepository;
	private FortifySingleAppRepository fortifySingleAppRepository;
	private StatusRepository statusRepository;
	private SecureRestTemplate secureRestTemplate;
	private ScannerTypeRepository scannerTypeRepository;
	private BugTrackerRepository bugTrackerRepository;
	private List<BugTracking> bugTrackings ;
	private CiOperationsRepository ciOperationsRepository;
	private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
	private SimpleDateFormat sdfForFortify = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
	private String[] blackListedLocation = new String[] {"src","source","vendor","lib" };


	FortifyApiClient(VaultHelper vaultHelper, ScannerRepository scannerRepository, CodeVulnRepository codeVulnRepository, List<BugTracking> bugTrackings, DependencyTrackApiClient dependencyTrackApiClient,
					 CodeProjectRepository codeProjectRepository, CodeGroupRepository codeGroupRepository, FortifySingleAppRepository fortifySingleAppRepository,
					 StatusRepository statusRepository, SecureRestTemplate secureRestTemplate, ScannerTypeRepository scannerTypeRepository,
					 BugTrackerRepository bugTrackerRepository, CiOperationsRepository ciOperationsRepository){
		this.vaultHelper = vaultHelper;
		this.bugTrackerRepository = bugTrackerRepository;
		this.scannerRepository = scannerRepository;
		this.codeVulnRepository = codeVulnRepository;
		this.codeProjectRepository = codeProjectRepository;
		this.bugTrackings = bugTrackings;
		this.codeGroupRepository = codeGroupRepository;
		this.fortifySingleAppRepository = fortifySingleAppRepository;
		this.statusRepository = statusRepository;
		this.secureRestTemplate = secureRestTemplate;
		this.scannerTypeRepository = scannerTypeRepository;
		this.ciOperationsRepository = ciOperationsRepository;
	}

	private JsonObject unifiedTokenObject = new JsonObject();
	private TokenValidator tokenValidator = new TokenValidator();

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
		final String passwordToEncode = scanner.getUsername() + ":" + vaultHelper.getPassword(scanner.getPassword());
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
			CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
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
			ResponseEntity<String> response = codeRequestHelper
					.getRestTemplate()
					.exchange(url, HttpMethod.GET, codeRequestHelper.getHttpEntity(), String.class);
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
		} catch (HttpClientErrorException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException | URISyntaxException | HttpServerErrorException hcee){
			log.error("FortifySSC HttpClientErrorExceptio was unsuccessfull with code of: {} {} ",hcee.getLocalizedMessage(),hcee.getMessage());
		}
	}

	private void updateCiOperationsForDoneSastScan(CodeProject codeProject) {
		Optional<CiOperations> operations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject,codeProject.getCommitid());
		if (operations.isPresent()){
			CiOperations operation = operations.get();
			operation.setSastScan(true);
			operation.setSastCrit(codeVulnRepository.findByCodeProjectAndSeverityAndAnalysis(codeProject, Constants.VULN_CRITICALITY_CRITICAL, Constants.FORTIFY_ANALYSIS_EXPLOITABLE).size());
			operation.setSastHigh(codeVulnRepository.findByCodeProjectAndSeverityAndAnalysis(codeProject, Constants.VULN_CRITICALITY_HIGH, Constants.FORTIFY_ANALYSIS_EXPLOITABLE).size());
			ciOperationsRepository.save(operation);
			log.info("CI Operation updated for {} - {} settings SAST scan to true", codeProject.getCodeGroup().getProject().getName(),codeProject.getName());
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
			if(codeGroup.getHasProjects() && cp == null) {
				CodeProject codeProject = getProjectFromPath(codeGroup,vulnJson.getString(Constants.VULN_PATH));
				if (codeProject == null)
					return;
				vuln.setCodeProject(codeProject);
				vuln.setCodeGroup(codeGroup);
			}else if (codeGroup.getHasProjects() && cp != null){
				vuln.setCodeProject(cp);
				vuln.setCodeGroup(codeGroup);
			}else {
				vuln.setCodeGroup(codeGroup);
				List<CodeProject> codeProject = codeProjectRepository.findByCodeGroup(codeGroup);
				if (codeProject.size() == 1)
					vuln.setCodeProject(codeProject.get(0));
			}
			vuln.setFilePath(vulnJson.getString(Constants.VULN_PATH)+":"+vulnJson.getString(Constants.FORTIFY_LINE_NUMVER));
			vuln = createDescriptionAndState(vulnJson.getString(Constants.VULN_ISSUE_INSTANCE_ID),vulnJson.getLong(Constants.VULN_ISSUE_ID),
					codeGroup.getVersionIdAll(), scanner, vuln);
			codeVulnRepository.save(vuln);
		}

	}

	private CodeVuln createDescriptionAndState(String instanceId, Long id, int versionid, io.mixeway.db.entity.Scanner scanner, CodeVuln codeVuln) throws ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, IOException, URISyntaxException {
		StringBuilder issueDetails = new StringBuilder();
		codeVuln.setExternalId((id));
		CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
		ResponseEntity<IssueDetailDataModel> response = codeRequestHelper
				.getRestTemplate()
				.exchange(scanner.getApiUrl()+"/api/v1/issueDetails/"+id, HttpMethod.GET, codeRequestHelper.getHttpEntity(), IssueDetailDataModel.class);
		if (response.getStatusCode() == HttpStatus.OK) {
			issueDetails.append("Severity: ")
					.append(codeVuln.getSeverity());
			issueDetails.append("\n");
			issueDetails.append("\n");
			issueDetails.append("Full details: " + "https://fortifyssc.corpnet.pl/ssc/html/ssc/version/" + versionid + "/fix/" + id + "/?engineType=SCA&issue=" + instanceId + "&filterSet=a243b195-0a59-3f8b-1403-d55b7a7d78e6");
			issueDetails.append("\n");
			issueDetails.append("Full filename: ")
					.append(Objects.requireNonNull(response.getBody()).getIssueDetailModel().getFullFileName())
					.append(":").append(response.getBody().getIssueDetailModel().getLineNumber());
			issueDetails.append("\n");
			issueDetails.append("Details: ")
					.append(response.getBody().getIssueDetailModel().getDetail());
			issueDetails.append("\n");
			//issueDetails.append("CodeSnippet:\n ")
			//		.append(getCodeSnippet(scanner, versionid, response.getBody().getIssueDetailModel().getFullFileName(),
			//		response.getBody().getIssueDetailModel().getLineNumber()));
			codeVuln.setDescription(issueDetails.toString());
			codeVuln.setFilePath(response.getBody().getIssueDetailModel().getFullFileName()+":"+response.getBody().getIssueDetailModel().getLineNumber());
			if (response.getBody().getIssueDetailModel().getScanStatus().equals(Constants.FORTIFY_ISSUE_STATE_UPDATED)){
				codeVuln.setStatus(statusRepository.findByName(Constants.STATUS_EXISTING));
			} else {
				codeVuln.setStatus(statusRepository.findByName(Constants.STATUS_NEW));
				processIssueTracking(codeVuln);
				//TODO Auto jira generation
			}
		}

		return codeVuln;
	}

	private void processIssueTracking(CodeVuln codeVuln) throws URISyntaxException {
		if (codeVuln.getCodeGroup()!=null) {
			Optional<BugTracker> bugTracker = bugTrackerRepository.findByProjectAndVulns(codeVuln.getCodeGroup().getProject(), Constants.VULN_JIRA_CODE);
			if (bugTracker.isPresent() && codeVuln.getTicketId() == null) {
				for (BugTracking bugTracking : bugTrackings) {
					if (bugTracking.canProcessRequest(bugTracker.get())) {
						bugTracking.processRequest(codeVulnRepository, Optional.of(codeVuln), bugTracker.get(), codeVuln.getCodeGroup().getProject(), Constants.VULN_JIRA_CODE, Constants.SCAN_MODE_AUTO, false);
					}
				}
			}
		}
	}

	private String getCodeSnippet(io.mixeway.db.entity.Scanner scanner, int versionid, String fullFileName, int lineNumber) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
		String codeSnippet = "";
		CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
		ResponseEntity<FileContentDataModel> response = codeRequestHelper
				.getRestTemplate()
				.exchange(scanner.getApiUrl()+"/api/v1/projectVersions/"+versionid+"/sourceFiles?q=path:\""
				+fullFileName+"\"", HttpMethod.GET, codeRequestHelper.getHttpEntity(), FileContentDataModel.class);
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
		else if (!Arrays.stream(blackListedLocation).anyMatch(projectName::equals)) {
			CodeProject codeProjectNew = new CodeProject();
			codeProjectNew.setCodeGroup(group);
			codeProjectNew.setSkipAllScan(true);
			codeProjectNew.setName(projectName);
			codeProjectRepository.save(codeProjectNew);
			log.info("Creating project {} for group {}", projectName,group.getName());
			return codeProjectNew;
		} else
			return null;
	}
	//SSC - status of cloduscan job
	private boolean verifyCloudScanJob(CodeGroup cg) throws ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, IOException {
		try {
			io.mixeway.db.entity.Scanner scanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY)).get(0);
			CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
			String API_JOB_STATE = "/api/v1/cloudjobs";
			ResponseEntity<CloudJobState> response = codeRequestHelper
					.getRestTemplate()
					.exchange(scanner.getApiUrl() + API_JOB_STATE + "/" + cg.getScanid(), HttpMethod.GET, codeRequestHelper.getHttpEntity(), CloudJobState.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				if (Objects.requireNonNull(response.getBody()).getData().getJobState().equals(Constants.FORTIFY_UPLOAD_COMPLETED)) {
					log.info("CloudScan ended for {}", cg.getName());
					return true;
				} else if (response.getBody().getData().getJobState().equals(Constants.FORTIFY_SCAN_FOULTED) ||
						response.getBody().getData().getJobState().equals(Constants.FORTIFY_SCAN_FAILED) ||
						response.getBody().getData().getJobState().equals(Constants.FORTIFY_SCAN_CANCELED) ||
						response.getBody().getData().getJobState().equals(Constants.FORTIFY_UPLOAD_FAILED)) {
					cg.setRunning(false);
					cg.setRequestid(null);
					cg.setScanid(null);
					cg.setScope(null);
					codeGroupRepository.save(cg);
					updateRunningForCodeProjectsByCodeGroup(cg);
					log.info("CloudScan ended with FAULTED state for {}", cg.getName());
					return false;
				}
			}
			return false;
		} catch (HttpClientErrorException ex){
			log.debug("HttpClientErrorException during cloud scan job verification for {}",cg.getScanid());
		}
		return false;
	}

	private void updateRunningForCodeProjectsByCodeGroup(CodeGroup cg) {
		for (CodeProject codeProject : codeProjectRepository.findByCodeGroupAndRunning(cg,true)){
			codeProject.setRunning(false);
			codeProjectRepository.save(codeProject);
		}
	}

	private CodeRequestHelper prepareRestTemplate(io.mixeway.db.entity.Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
		Date fortifyTokenExpirationDate = sdf.parse(scanner.getFortifytokenexpiration()+".123");
		LocalDateTime fortifyTokenExpiration = LocalDateTime.ofInstant(fortifyTokenExpirationDate.toInstant(), ZoneId.systemDefault());
		if (tokenValidator.isTokenValid(scanner.getFortifytoken(), fortifyTokenExpiration)) {
			generateToken(scanner);
		}
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
		HttpHeaders headers = new HttpHeaders();
		headers.set(Constants.HEADER_AUTHORIZATION, Constants.FORTIFY_TOKEN + " " + scanner.getFortifytoken());
		HttpEntity entity = new HttpEntity(headers);

		return new CodeRequestHelper(restTemplate,entity);
	}

	private CreateFortifyScanRequest prepareScanRequestForGroup(CodeGroup cg){
		List<io.mixeway.db.entity.Scanner> fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY_SCA));
		CreateFortifyScanRequest fortifyScanRequest = new CreateFortifyScanRequest();
		fortifyScanRequest.setCloudCtrlToken(vaultHelper.getPassword(fortify.get(0).getFortifytoken()));
		fortifyScanRequest.setGroupName(cg.getName());
		fortifyScanRequest.setUsername(cg.getRepoUsername());
		fortifyScanRequest.setSingle(false);
		fortifyScanRequest.setPassword(vaultHelper.getPassword(cg.getRepoPassword()));
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
				pc.setdTrackUuid(cp.getdTrackUuid());
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
			fortifyScanRequest.setCloudCtrlToken(vaultHelper.getPassword(fortify.get(0).getFortifytoken()));
			fortifyScanRequest.setGroupName(cp.getCodeGroup().getName());
			fortifyScanRequest.setSingle(true);
			fortifyScanRequest.setdTrackUuid(cp.getdTrackUuid());
			fortifyScanRequest.setUsername(cp.getCodeGroup().getRepoUsername());
			fortifyScanRequest.setPassword(vaultHelper.getPassword(cp.getCodeGroup().getRepoPassword()));
			fortifyScanRequest.setVersionId(cp.getCodeGroup().getVersionIdsingle()>0 ? cp.getCodeGroup().getVersionIdsingle() : cp.getCodeGroup().getVersionIdAll() );
			ProjectCode pc = new ProjectCode();
			pc.setTechnique(cp.getTechnique());
			pc.setdTrackUuid(cp.getdTrackUuid());
			pc.setBranch(cp.getBranch() != null && !cp.getBranch().equals("") ? cp.getBranch() : Constants.CODE_DEFAULT_BRANCH);
			pc.setProjectRepoUrl(cp.getRepoUrl());
			pc.setProjectName(cp.getName());
			fortifyScanRequest.setProjects(Collections.singletonList(pc));
			return fortifyScanRequest;
		} else
			return null;
	}
	@Override
	@Transactional(propagation = Propagation.REQUIRES_NEW)
	public boolean isScanDone(CodeGroup cg, CodeProject cp) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, ParseException, JSONException {
		if ((cg != null && StringUtils.isNotBlank(cg.getScanid())) || (cp !=null && StringUtils.isNotBlank(cp.getCodeGroup().getScanid()))){
			return verifyCloudScanJob(cg != null? cg : cp.getCodeGroup());
		} else {
			if (cp == null && cg!= null && getScanIdForCodeGroup(cg) && verifyCloudScanJob(cg)) {
				return true;
			} else if (cg == null && cp != null && getScanIdForCodeProject(cp) && verifyCloudScanJob(cp.getCodeGroup())) {
				return true;
			}
		}
		return false;
	}

	@Transactional(propagation = Propagation.REQUIRES_NEW)
	public boolean getScanIdForCodeProject(CodeProject cp) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		List<io.mixeway.db.entity.Scanner> fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY_SCA));
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
		ResponseEntity<FortifyScan> response = restTemplate.exchange(fortify.get(0).getApiUrl()+"/check/"+cp.getRequestId(), HttpMethod.GET, null, FortifyScan.class);

		if (response.getStatusCode().equals(HttpStatus.OK)) {
			if (Objects.requireNonNull(response.getBody()).getError() != null && response.getBody().getError()) {
				cp.setRunning(false);
				codeProjectRepository.save(cp);
				return false;
			} else if (response.getBody().getScanId() != null && response.getBody().getCommitid()!=null) {
				CodeGroup codeGroup = cp.getCodeGroup();
				codeGroup.setScanid(response.getBody().getScanId());
				codeGroupRepository.saveAndFlush(codeGroup);
				cp.setCommitid(response.getBody().getCommitid());
				cp.setCodeGroup(codeGroup);
				codeProjectRepository.save(cp);
				createCiOperation(cp, response.getBody().getCommitid());
				log.info("Fortify scan was passed to cloudscan for [scope {}] {} scan id {} ", cp.getName(), cp.getCodeGroup().getName(),codeGroup.getScanid());
				return true;
			}
		}
		return false;
	}

	private boolean getScanIdForCodeGroup(CodeGroup cg) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		List<io.mixeway.db.entity.Scanner> fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY_SCA));
		RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
		ResponseEntity<FortifyScan> response = restTemplate.exchange(fortify.get(0).getApiUrl()+"/check/"+cg.getRequestid(), HttpMethod.GET, null, FortifyScan.class);

		if (response.getStatusCode().equals(HttpStatus.OK)) {
			if (Objects.requireNonNull(response.getBody()).getError() != null && response.getBody().getError()) {
				cg.setRunning(false);
				codeGroupRepository.save(cg);
				return false;
			} else if (response.getBody().getScanId() != null) {
				cg.setScanid(response.getBody().getScanId());
				codeGroupRepository.save(cg);
				log.info("Fortify scan was passed to cloudscan for [scope {}] {} ", cg.getScope(), cg.getName());
				return true;
			}
		}
		return false;

	}

	@Override
	public boolean canProcessRequest(CodeGroup cg) {
		Optional<io.mixeway.db.entity.Scanner> fortify = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY_SCC)).stream().findFirst();
		return fortify.isPresent();
	}

	@Override
	public boolean canProcessRequest(Scanner scanner) {
		return (scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_FORTIFY_SCA) || scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_FORTIFY)) && scanner.getStatus();
	}

	@Override
	public boolean canProcessInitRequest(Scanner scanner) {
		return (scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_FORTIFY_SCA) || scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_FORTIFY));
	}

	@Override
	public List<SASTProject> getProjects(Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
		List<SASTProject> sastProjects = new ArrayList<>();
		try {
			CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);

			String API_GET_VERSIONS = "/api/v1/projectVersions";
			ResponseEntity<FortifyProjectVersionDto> response = codeRequestHelper
					.getRestTemplate()
					.exchange(scanner.getApiUrl() + API_GET_VERSIONS, HttpMethod.GET, codeRequestHelper.getHttpEntity(), FortifyProjectVersionDto.class);
			if (response.getStatusCode() == HttpStatus.OK) {
				for (FortifyProjectVersions fpv : Objects.requireNonNull(response.getBody()).getFortifyProjectVersions()) {
					SASTProject sastProject = new SASTProject(fpv.getId(), fpv.getProject().getName() + " - " + fpv.getName());
					sastProjects.add(sastProject);
				}
			}
		} catch (Exception e) {
			log.error("Exception came up during getting Fortify SSC projects");
		}
		return sastProjects;
	}

	@Override
	public boolean createProject(Scanner scanner, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
		try {
			CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
			List<SASTProject> sastProjects = new ArrayList<>();
			HttpEntity<FortifyProjectVersions> entity = new HttpEntity<>(new FortifyProjectVersions(codeProject, scanner), codeRequestHelper.getHttpEntity().getHeaders());
			String API_GET_VERSIONS = "/api/v1/projectVersions";
			ResponseEntity<FortifyCreateProjectResponse> response = codeRequestHelper
					.getRestTemplate()
					.exchange(scanner.getApiUrl() + API_GET_VERSIONS, HttpMethod.POST, entity, FortifyCreateProjectResponse.class);
			if (response.getStatusCode() == HttpStatus.CREATED &&
					fortifyCreateAttributes(scanner,codeProject, response.getBody().getFortifyProjectVersions().getId()) &&
					fortifyCommitProject(scanner, codeProject, response.getBody().getFortifyProjectVersions().getId())) {
				codeProject.getCodeGroup().setVersionIdAll(response.getBody().getFortifyProjectVersions().getId());
				codeGroupRepository.save(codeProject.getCodeGroup());
				log.info("Successfully created Fortify SSC Project for {} with id {}", codeProject.getCodeGroup().getName(), codeProject.getCodeGroup().getVersionIdAll());
				return true;
			}
		} catch (HttpClientErrorException e){
			log.warn("Exception during FortifySSC project creation - {}", e.getLocalizedMessage());
		}
		return false;
	}

	@Override
	public void putInformationAboutScanFromRemote(CodeProject codeProject, CodeGroup codeGroup, String jobId) {
		codeGroup.setScope(codeProject.getName());
		codeGroup.setRunning(true);
		codeGroup.setScanid(jobId);
		codeGroup.setRequestid("xx");
		codeGroupRepository.saveAndFlush(codeGroup);
		codeProject.setRunning(true);
		codeProject.setRequestId("xx");
		codeProjectRepository.saveAndFlush(codeProject);
		FortifySingleApp fortifySingleApp = new FortifySingleApp();
		fortifySingleApp.setCodeGroup(codeGroup);
		fortifySingleApp.setCodeProject(codeProject);
		fortifySingleApp.setRequestId("XXX");
		fortifySingleApp.setJobToken(jobId);
		fortifySingleApp.setFinished(true);
		fortifySingleApp.setDownloaded(false);
		fortifySingleAppRepository.saveAndFlush(fortifySingleApp);
		log.info("Successfully put job {} from remote regarding {} / {}", LogUtil.prepare(jobId), LogUtil.prepare(codeGroup.getName()),LogUtil.prepare(codeProject.getName()));
	}

	private boolean fortifyCommitProject(Scanner scanner, CodeProject codeProject, int versionId) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
		try {
			CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
			HttpEntity<FortifyProjectVersions> entity = new HttpEntity<>(new FortifyProjectVersions(codeProject, scanner), codeRequestHelper.getHttpEntity().getHeaders());
			String API_GET_VERSIONS = "/api/v1/projectVersions/"+versionId;
			ResponseEntity<String> response = codeRequestHelper
					.getRestTemplate()
					.exchange(scanner.getApiUrl() + API_GET_VERSIONS, HttpMethod.PUT, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK ) {
				return true;
			}
		} catch (HttpClientErrorException e){
			log.warn("Exception during FortifySSC project creation - {}", e.getLocalizedMessage());
		}
		return false;
	}

	private boolean fortifyCreateAttributes(Scanner scanner, CodeProject codeProject, int versionId)throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
		try {
			List<FortifyProjectAttributes> fortifyProjectAttributes = new ArrayList<>();
			fortifyProjectAttributes.add(new FortifyProjectAttributes("DevPhase",5,"New"));
			fortifyProjectAttributes.add(new FortifyProjectAttributes("DevPhase",6,"Internal"));
			fortifyProjectAttributes.add(new FortifyProjectAttributes("DevPhase",7,"internalnetwork"));
			fortifyProjectAttributes.add(new FortifyProjectAttributes("DevPhase",1,"High"));
			CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
			List<SASTProject> sastProjects = new ArrayList<>();
			HttpEntity<List<FortifyProjectAttributes>> entity = new HttpEntity<>(fortifyProjectAttributes, codeRequestHelper.getHttpEntity().getHeaders());
			String API_GET_VERSIONS = "/api/v1/projectVersions/" + versionId + "/attributes";
			ResponseEntity<String> response = codeRequestHelper
					.getRestTemplate()
					.exchange(scanner.getApiUrl() + API_GET_VERSIONS, HttpMethod.PUT, entity, String.class);
			if (response.getStatusCode() == HttpStatus.OK ) {
				return true;
			}
		} catch (HttpClientErrorException e){
			log.warn("Exception during FortifySSC project creation - {}", e.getLocalizedMessage());
		}
		return false;
	}

	@Override
	public boolean canProcessRequest(ScannerType scannerType) {
		return scannerType.getName().equals(Constants.SCANNER_TYPE_FORTIFY) || scannerType.getName().equals(Constants.SCANNER_TYPE_FORTIFY_SCA);
	}

	@Override
	public void saveScanner(ScannerModel scannerModel) throws Exception {
		List<Scanner>  scanners = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true);
		if (scanners.stream().findFirst().isPresent()){
			throw new Exception(Constants.SAST_SCANNER_ALREADY_REGISTERED);
		} else {
			ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
			if (scannerType.getName().equals(Constants.SCANNER_TYPE_FORTIFY)) {
				io.mixeway.db.entity.Scanner fortify = new io.mixeway.db.entity.Scanner();
				fortify.setApiUrl(scannerModel.getApiUrl());
				fortify.setUsername(scannerModel.getUsername());
				fortify.setStatus(false);
				fortify.setScannerType(scannerType);
				// api key put to vault
				String uuidToken = UUID.randomUUID().toString();
				if (vaultHelper.savePassword(scannerModel.getPassword(), uuidToken)){
					fortify.setPassword(uuidToken);
				} else {
					fortify.setPassword(scannerModel.getPassword());
				}
				scannerRepository.save(fortify);
			} else if (scannerType.getName().equals(Constants.SCANNER_TYPE_FORTIFY_SCA)) {
				io.mixeway.db.entity.Scanner fortify = new io.mixeway.db.entity.Scanner();
				fortify.setApiUrl(scannerModel.getApiUrl());
				fortify.setStatus(false);
				fortify.setScannerType(scannerType);
				// api key put to vault
				String uuidToken = UUID.randomUUID().toString();
				if (vaultHelper.savePassword(scannerModel.getCloudCtrlToken(),uuidToken)){
					fortify.setFortifytoken(uuidToken);
				} else {
					fortify.setFortifytoken(scannerModel.getCloudCtrlToken());
				}
				scannerRepository.save(fortify);
			}
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
			} else if (response.getBody().getScanId() != null) {
				if (response.getBody().getProjectName() != null ) {
					Optional<CodeProject> cp = codeProjectRepository.findByCodeGroupAndName(cg, response.getBody().getProjectName());
					if (cp.isPresent()) {
						cp.get().setCommitid(response.getBody().getCommitid());
						createCiOperation(cp.get(), response.getBody().getCommitid());
						codeProjectRepository.save(cp.get());
						FortifySingleApp fortifySingleApp = new FortifySingleApp();
						fortifySingleApp.setCodeGroup(cg);
						fortifySingleApp.setCodeProject(cp.get());
						fortifySingleApp.setRequestId(response.getBody().getRequestId());
						fortifySingleApp.setJobToken(response.getBody().getScanId());
						fortifySingleApp.setFinished(false);
						fortifySingleApp.setDownloaded(false);
						fortifySingleAppRepository.saveAndFlush(fortifySingleApp);
						cp.get().setRunning(false);
						codeProjectRepository.saveAndFlush(cp.get());
						codeGroupRepository.saveAndFlush(cg);
					}
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

	private void createCiOperation(CodeProject codeProject, String commitid) {
		Optional<CiOperations> operation = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject,commitid);
		if (!operation.isPresent() && StringUtils.isNotBlank(commitid)) {
			CiOperations newOperation = new CiOperations();
			newOperation.setProject(codeProject.getCodeGroup().getProject());
			newOperation.setCodeGroup(codeProject.getCodeGroup());
			newOperation.setCodeProject(codeProject);
			newOperation.setCommitId(commitid);
			ciOperationsRepository.save(newOperation);
			log.info("Creating CI Operation for {} - {} with commitid {}", newOperation.getProject().getName(), newOperation.getCodeProject().getName(), LogUtil.prepare(commitid));
		}
	}

	@Override
	public Boolean runScan(CodeGroup cg,CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
		List<Scanner> fortify = scannerRepository
				.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY_SCA));
		Optional<Scanner>fortifySSC = scannerRepository
				.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_FORTIFY_SCC)).stream().findFirst();
		Optional<Scanner> dTrack = scannerRepository
				.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK)).stream().findFirst();
		if (codeGroupRepository.countByRunning(true) ==0 && codeProjectRepository.findByRunning(true).size() ==0 && fortify.size()>0 && fortifySSC.isPresent()) {
			if (canRunScan(cg,codeProject)) {
				CreateFortifyScanRequest fortifyScanRequest;
				String scope;
				if (codeProject == null && cg != null) {
					fortifyScanRequest = prepareScanRequestForGroup(cg);
					scope = Constants.FORTIFY_SCOPE_ALL;
				} else {
					fortifyScanRequest = prepareScanRequestForProject(codeProject);
					scope = codeProject.getName();
				}
				fortifyScanRequest.setSscUrl(fortifySSC.get().getApiUrl());
				if (dTrack.isPresent()){
					fortifyScanRequest.setdTrackUrl(dTrack.get().getApiUrl());
					fortifyScanRequest.setdTrackToken(vaultHelper.getPassword(dTrack.get().getApiKey()));
				}
				try {
					RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
					HttpHeaders headers = new HttpHeaders();
					headers.set("Content-Type", "application/json");
					HttpEntity<CreateFortifyScanRequest> entity = new HttpEntity<>(fortifyScanRequest, headers);
					ResponseEntity<FortifyScan> response = restTemplate.exchange(fortify.get(0).getApiUrl() + "/createscan", HttpMethod.PUT, entity, FortifyScan.class);
					if (response.getStatusCode().equals(HttpStatus.OK) && Objects.requireNonNull(response.getBody()).getRequestId() != null) {
						if (codeProject!=null){
							codeProject.setRunning(true);
							codeProject.setRequestId(response.getBody().getRequestId());
							codeProjectRepository.saveAndFlush(codeProject);
						} else {
							cg.setRequestid(response.getBody().getRequestId());
							cg.setRunning(true);
							cg.setScope(scope);
							codeGroupRepository.saveAndFlush(cg);
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

	private boolean canRunScan(CodeGroup cg, CodeProject codeProject) {
		if ( codeProject != null && codeProject.getRunning() )
			return false;
		else if (cg!= null && cg.isRunning())
			return false;
		else return true;
	}
}
