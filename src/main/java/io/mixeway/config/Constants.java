package io.mixeway.config;

public class Constants {
	public static final String HOSTS = "hosts";
	public static final String TARGET_NAME = "name";
	public static final String TARGET_ID = "target_id";
	public static final String CONFIG_ID = "config_id";
	public static final String SCANNER_ID = "scanner_id";
	public static final String TASK_ID = "task_id";
	public static final String REPORT_ID = "report_id";
	public static final String STATUS = "status";
	public static final String STATUS_DONE = "Done";
	public static final String STATUS_RUNNING = "Running";
	public static final String STATUS_REQUESTED = "Requested";
	public static final String SCAN_MODE_AUTO = "Automatic";
	public static final String SCAN_MODE_MANUAL = "Manual";
	public static final String IF_VULNS = "vulns";
	public static final String IF_VULN_NAME = "name";
	public static final String IF_VULN_THREAT = "threat";
	public static final String IF_VULN_PORT = "port";
	public static final String IF_VULN_HOST = "host";
	public static final String IF_VULN_DESC = "desc";
	public static final String IF_VULN_THREAT_HIGH = "High";
	public static final String IF_VULN_THREAT_MEDIUM = "Medium";
	public static final String SOFTWARE_LOOKUP_UPDATE= "Detection";
	public static final String HEADER_CONTENT_TYPE = "Content-Type";
	public static final String HEADER_CONTENT_TYPE_JSON = "application/json";
	public static final String HEADER_AUTHORIZATION = "Authorization";

	//ROUTING DOMAINS
	public static final String DOMAIN_INTERNET = "Internet";
	
	//FORTIFY
	public static final String VULNERABILITIES_LIST = "data";
	public static final String VULN_PATH = "fullFileName";
	public static final String VULN_CRITICALITY = "friority";
	public static final String VULN_ANALYSIS = "primaryTag";
	public static final String VULN_NAME = "issueName";
	public static final String VULN_CRITICALITY_CRITICAL = "Critical";
	public static final String VULN_CRITICALITY_HIGH = "High";
	public static final String FORTIFY_TOKEN = "FortifyToken";
	public static final String VULN_ISSUE_ID = "id";
	public static final String VULN_ISSUE_INSTANCE_ID="issueInstanceId";
	public static final String FORTIFY_LINKS = "links";
	public static final String FORTIFY_LINKS_NEXT = "next";
	public static final String FORTIFY_LINKS_NEXT_HREF = "href";
	public static final String FORTIFY_ANALYSIS_EXPLOITABLE = "Exploitable";
	public static final String FORTIFY_SCOPE_ALL = "ALL";
	public static final String FORTIFY_LINE_NUMVER = "lineNumber";

	//CHECKMARX
	public static final String BEARER_TOKEN = "Bearer";

	//VULN HISTORY
	public static final String VULN_HISTORY_ALL = "complete";

	//SCANER TYPES
	public static final String SCANNER_TYPE_OPENVAS = "OpenVAS";
	public static final String SCANNER_TYPE_OPENVAS_SOCKET = "OpenVAS Socket";
	public static final String SCANNER_TYPE_NESSUS = "Nessus";
	public static final String SCANNER_TYPE_FORTIFY = "Fortify SSC";
	public static final String SCANNER_TYPE_ACUNETIX = "Acunetix";
	public static final String SCANNER_TYPE_NEXPOSE = "Nexpose";
	public static final String SCANNER_TYPE_FORTIFY_SCA = "Fortify SCA Rest API";
	
	//ACUNETIX
	public static final String ACUNETIX_TARGET_ID = "target_id";
	public static final String ACUNETIX_UPLOAD_URL = "upload_url";
	public static final String ACUNETIX_CONFIGURE_KIND = "kind";
	public static final String ACUNETIX_CONFIGURE_KIND_LOGIN = "sequence";
	public static final String ACUNETIX_CONFIGURE_LOGIN = "login";
	public static final String ACUNETIX_PROXY = "proxy";
	public static final String ACUNETIX_PROXY_ENABLED = "enabled";
	public static final String ACUNETIX_PROXYPROTOCOL = "protocol";
	public static final String ACUNETIX_PROXY_PORT = "port";
	public static final String ACUNETIX_PROXY_ADDRESS = "address";
	public static final String ACUNETIX_TARGET_SCAN_ID = "last_scan_id";
	public static final String ACUNETIX_TARGET_SCAN_STATUS = "last_scan_session_status";
	public static final String ACUNETIX_TARGET_SCAN_STATUS_COMPLETED = "completed";
	public static final String ACUNETIX_TARGET_SCAN_STATUS_FAILED = "failed";
	public static final String ACUNETIX_VULN = "vulnerabilities";
	public static final String ACUNETIX_VULN_NAME = "vt_name";
	public static final String ACUNETIX_VULN_LOCATION = "affects_url";
	public static final String ACUNETIX_VULN_DESCRIPTION = "description";
	public static final String ACUNETIX_VULN_RECOMMENDATION = "recommendation";
	public static final String ACUNETIX_VULN_ID = "vuln_id";
	public static final String ACUNETIX_SEVERITY = "severity";
	public static final int WEBAPP_SCAN_LIMIT = 15;
	public static final String ACUNETIX_PAGINATION = "pagination";
	public static final String ACUNETIX_NETX_CURSOR = "next_cursor";
	public static final String ACUNETIX_IMPACT = "impact";
	public static final String ACUNETIX_REQUEST = "request";
	
	// API TYPES
	public static final String API_TYPE_CIS_K8S = "cis-k8s";
	public static final String API_SCANNER_OPENVAS = "networkScanner";
	public static final String API_SCANNER_WEBAPP = "webApplicationScanner";
	public static final String API_SCANNER_OPENSOURCE = "openSourceScanner";
	public static final String API_SCANNER_CODE = "codeScanner";
	public static final String API_SCANNER_AUDIT = "audit";
	public static final String API_SCANNER_PACKAGE = "packageScan";
	public static final String API_SEVERITY_CRITICAL = "Critical";
	public static final String API_SEVERITY_HIGH = "High";
	public static final String API_SEVERITY_MEDIUM = "Medium";
	public static final String API_SEVERITY_LOW = "Low";
	public static final String API_SEVERITY_INFO = "Info";
	
	//NESSUS
	public static final String NESSUS_FOLDER = "Mixer-Scanner";
	public static final String NESSUS_APIKEYS = "X-ApiKeys";
	public static final String NESSUS_ID = "id";
	public static final String NESSUS_TEMPLATES = "templates";
	public static final String NESSUS_TEMPLATE_TITLE = "title";
	public static final String NESSUS_TEMPLATE_BASIC_NETOWRK = "Basic Network Scan";
	public static final String NESSUS_UUID = "uuid";
	public static final String NESSUS_SCAN = "scan";
	public static final String NESSUS_SCAN_INFO = "info";
	public static final String NESSUS_SCAN_STATUS="status";
	public static final String NESSUS_SCAN_STATUS_COMPLETED = "completed";
	public static final String NESSUS_SCAN_STATUS_ABORTED = "aborted";
	public static final String NESSUS_HOSTS = "hosts";
	public static final String NESSUS_HOSTNAME = "hostname";
	public static final String NESSUS_HOST_ID = "host_id";
	public static final String NESSUS_VULNERABILITIES = "vulnerabilities";
	public static final String NESSUS_PLUGIN_ID = "plugin_id";
	public static final String NESSUS_PLUGIN_NAME = "plugin_name";
	public static final String NESSUS_SEVERITY = "severity";
	public static final String NESSUS_PORTS = "ports";
	public static final String NESSUS_OUTPUTS = "outputs";
	public static final String NESSUS_PLUGINDESCRIPTION = "plugindescription";
	public static final String NESSUS_PLUGINATTRIBUTES = "pluginattributes";
	public static final String NESSUS_VULN_DESCRIPTION = "description";
	public static final String NESSUS_OS_IDENTIFICATION = "OS Identification" ;
	public static final String NESSUS_PLUGIN_OUTPUT = "plugin_output";


	//CIS
	public static final String CIS_DOCKER_NAME = "cis-docker";
	public static final String CIS_DOCKER_NODE_NAME = "Docker";
	
	//ENUMS
	public static final String ASSET_IP_SINGLE = "SINGLE";

	//NEXPOSE
	public static final String NEXPOSE_ENGINE_NAME = "Local scan engine";
	public static final String NEXPOSE_TEMPLATE_NAME = "Full audit without Web Spider";
	public static final String NEXPOSE_IMPORTANCE_HIGH = "high";
	public static final String NEXPOSE_SITE_DESCRIPTION = "Automaticly generated site from MixingSecurity";
	public static final String NEXPOSE_SEVERITY_SEVERE="Severe";
	public static final String NEXPOSE_SEVERITY_MODERATE = "Moderate";
	public static final String NEXPOSE_STATUS_END = "finished";
	public static final String STATUS_NEW = "NEW" ;
	public static final String STATUS_EXISTING = "EXISTING" ;

	//FRONTEND
	public static final String INFRA_VULN_TREND_LABEL = "Infrastructure";
	public static final String WEBAPP_VULN_TREND_LABEL = "WebApps";
	public static final String CODE_VULN_TREND_LABEL = "Source Code";
	public static final String AUDIT_VULN_TREND_LABEL = "CIS Benchmark";
	public static final String SOFT_VULN_TREND_LABEL = "OpenSource";
	public static final String LOG_SEVERITY = "Log";
	public static final String INFO_SEVERITY = "Info";


    public static final String CODE_DEFAULT_BRANCH = "master" ;
    public static final String FORTIFY_NOT_AN_ISSUE = "Not an Issue" ;
    public static final String REQUEST_SCAN_WEBAPP = "webApp";
	public static final String REQUEST_SCAN_NETWORK = "network";
	public static final String REQUEST_SCAN_CODE = "code";
    public static final String STATUS_QUEUED = "In Queue";

	public static final String ROLE_USER = "ROLE_USER";
	public static final String ROLE_PROJECT_OWNER = "ROLE_PROJECT_OWNER";
	public static final String ROLE_EDITOR_RUNNER = "ROLE_EDITOR_RUNNER";
	public static final String ROLE_ADMIN = "ROLE_ADMIN";

	public static final String API_URL="api";
	public static final String KOORDYNATOR_API_URL = "koordynator";
	public static final String SCANMANAGE_API = "scanmanage";
    public static final String FORTIFY_ISSUE_STATE_UPDATED = "UPDATED";
    public static final String VULN_CRITICALITY_MEDIUM = "Medium";
	public static final String VULN_CRITICALITY_LOW = "Low";
	public static final String VULN_JIRA_INFRASTRUCTURE = "infra";
	public static final String VULN_JIRA_WEBAPP = "webapp";
	public static final String VULN_JIRA_CODE = "code";
	public static final String VULN_JIRA_OPENSOURCE = "opensource";
	public static final String OPENVAS_DEFAULT_CONFIG = "Full and fast";
	public static final String OPENVAS_DEFAULT_SCANNER = "OpenVAS Default";

    public static final String JIRA = "JIRA";
    public static final String FORTIFY_UPLOAD_COMPLETED = "UPLOAD_COMPLETED";
    public static final String FORTIFY_SCAN_FOULTED = "SCAN_FAULTED";
    public static final String FORTIFY_SCAN_FAILED = "SCAN_FAILED";
	public static final String FORTIFY_SCAN_CANCELED = "SCAN_CANCELED";
	public static final String FORTIFY_UPLOAD_FAILED = "UPLOAD_FAILED";
    public static final String SCANNER_TYPE_DEPENDENCYTRACK = "OWASP Dependency Track";
    public static final String DTRACK_AUTH_HEADER = "X-Api-Key";
    public static final String SCANNER_TYPE_CHECKMARX = "Checkmarx";
    public static final String SCANNER_TYPE_NEXUS_IQ = "Nexus-IQ";

    //Checmkarx
	public static final String CHECKMARX_LOGIN_FORM_USERNAME = "username";
	public static final String CHECKMARX_LOGIN_FORM_PASSWORD = "password";
	public static final String CHECKMARX_LOGIN_FORM_GRANT_TYPE = "grant_type";
	public static final String CHECKMARX_LOGIN_FORM_SCOPE = "scope";
	public static final String CHECKMARX_LOGIN_FORM_CLIENTID = "client_id";
	public static final String CHECKMARX_LOGIN_FORM_CLIENTSECRET = "client_secret";
	public static final String CHECKMARX_LOGIN_FORM_GRANT_TYPE_VALUE = "password";
	public static final String CHECKMARX_LOGIN_FORM_SCOPE_VALUE = "sast_rest_api";
	public static final String CHECKMARX_LOGIN_FORM_CLIENTID_VALUE = "resource_owner_client";
	public static final String CHECKMARX_LOGIN_FORM_CLIENTSECRET_VALUE = "014DF517-39D1-4453-B7B3-9930C563627C";
    public static final String CX_GET_TEAMS_API = "/cxrestapi/auth/teams";
    public static final String CX_LOGIN_API = "/cxrestapi/auth/identity/connect/token";
    public static final String CX_GET_PROJECTS_API = "/cxrestapi/projects";
    public static final String CX_CREATE_PROJECT_API = "/cxrestapi/projects";
    public static final String CX_CREATE_GIT_FOR_PROJECT_API = "/cxrestapi/projects/projectid/sourceCode/remoteSettings/git";
    public static final String CX_CREATE_SCAN_API = "/cxrestapi/sast/scans";
    public static final String CX_GET_SCAN_API = "/cxrestapi/sast/scans/scanid";
    public static final String CX_GET_REPORT_STATUS_API = "/cxrestapi/reports/sastScan/reportid/status";
    public static final String CX_GNERATE_REPORT_API = "/cxrestapi/reports/sastScan";
    public static final String CX_GET_RESULTS_API = "/cxrestapi/reports/sastScan/reportid";
    public static final String CX_PROJECTID = "projectid";
    public static final String CX_SCANID = "scanid";
    public static final String CX_REPORTID = "reportid";
    public static final String CX_SCAN_COMMENT = "Scan requested from Mixeway";
	public static final String CX_REPORT_TYPE = "CSV";
	public static final String CX_STATUS_FINISHED = "Finished";
	public static final String CX_REPORT_QUERY = "Query";
	public static final String CX_REPORT_DSTFILE = "DestFileName";
	public static final String CX_REPORT_DSTLINENO = "DestLine";
	public static final String CX_REPORT_ANALYSIS = "Result State";
	public static final String CX_REPORT_SEVERITY = "Result Severity";
	public static final String CX_REPORT_DESCRIPTION = "Link";

    public static final String CX_REPORT_STATE = "Result Status";
    public static final String SAST_SCANNER_ALREADY_REGISTERED = "Current Version of Mixeway support only one instance of SAST Scanner";
    public static final String CREATED_BY_MIXEWAY = "Created by Mixeway";
    public static final String FORTIFY_ISSUE_TEMPLATE = "Prioritized-HighRisk-Project-Template";
    public static final String SCANNER_TYPE_FORTIFY_SCC = "Fortify SSC";
    public static final String PROFILE_TEST = "test";
    public static final String DEFAULT = "default";
	public static final String PASSWORD = "password";
    public static final String CODE_PROJECT_DEFAULT_BRANCH = "master";
    public static final String AUTH_TYPE_JWT_TOKEN = "jwt";
	public static final String AUTH_TYPE_APIKEY = "apiKey";
	public static final String AUTH_TYPE_X509 = "x509";
    public static final Object PROJECT_KEYWORD = "project";
    public static final String ORIGIN_API = "API";
    public static final String ORIGIN_GUI = "GUI";
    public static final String ORIGIN_SCHEDULER = "SCHEDULER";
    public static final String STRATEGY_GUI = "GUI";
    public static final String STRATEGY_API = "API";
	public static final String STRATEGY_SCHEDULER = "SCHEDULER";
	public static final String SCANER_CATEGORY_WEBAPP = "WEBAPP";
	public static final String SCANER_CATEGORY_NETWORK = "NETWORK";
	public static final String SCANER_CATEGORY_CODE = "CODE";
	public static final String SCANER_CATEGORY_OPENSOURCE = "OPENSOURCE";

    public static final String ACUNETIX_TARGET_SCAN_STATUS_ABORTED = "aborted";
    public static final String SCANNER_TYPE_BURP = "Burp Enterprise Edition";
    public static final String BURP_SCAN_RUNNING = "RUNNING";
	public static final String BURP_SCAN_QUEUED = "QUEUED";
	public static final String BURP_CONFIG_CRAWL = "Crawl strategy - fastest";
	public static final String BURP_CONFIG_AUDIT = "Audit checks - light active";
    public static final String BURP_NAMED_CONFIGURATION = "NamedConfiguration";
	public static final String BURP_STATUS_FAILED = "failed";
	public static final String BURP_STATUS_SUCCEEDED = "succeeded";
    public static final String ROLE_API = "ROLE_API";
    public static final String VULN_TYPE_OPENSOURCE = "OpenSource";
    public static final String VULN_TYPE_SOURCECODE = "SourceCode";
    public static final String VULN_TYPE_WEBAPP = "WebApplication";
    public static final String VULN_TYPE_NETWORK = "Network";
    public static final String VULN_TYPE_OSPACKAGE = "OSPackage";
    public static final String STATUS_REMOVED = "REMOVED";
    public static final String IAAS_API_TYPE_AWS_EC2 = "AWS EC2";
	public static final String IAAS_API_TYPE_OPENSTACK = "OpenStack";
    public static final String AWS_VPC_ID = "vpc-id";
	public static final String AWS_STATE_RUNNING = "running";
    public static final String AWS_STATE_INUSE = "in-use";
    public static final String CI_SCOPE_OPENSOURCE = "opensource";
	public static final String CI_SCOPE_SAST = "sast";
    public static final String DUMMY_PASSWORD = "thisisdummypassword";
    public static final String CICD = "CICD";
    public static final String ROLE_API_CICD = "ROLE_API_CICD";
    public static final String PROJECT_UNKNOWN = "unknown";
    public static final String ROLE_AUDITOR = "ROLE_AUDITOR";
    public static final String VULNEARBILITY_SOURCE_GITLEAKS = "GitLeaks";
    public static final String VULNEARBILITY_SOURCE_CISBENCHMARK = "CISBenchmark";
    public static final String STATUS_STOPPED = "Stopped";
    public static final String CX_STATUS_CREATED = "Created";
	public static final String CX_ANALYSIS_TO_VERIFY = "To Verify";
	public static final String CX_ANALYSIS_NOT_EXPLOITABLE = "Not Exploitable";
	public static final String CX_ANALYSIS_CONFIRMED = "Confirmed";
	public static final String CX_ANALYSIS_URGENT = "Urgent";
	public static final String CX_ANALYSIS_FP = "Proposed Not Exploitable";
    public static final String SECURITY_GATEWAY_PASSED = "Security Policy (scope Source Code and Open Source) is passed. Congratz!";
    public static final String SECURITY_GATEWAY_FAILED = "Security Policy (scope Source Code and Open Source) is NOT passed. Vulnerabilities are listed above, please fix them before proceeding.";
    public static final String DEFAULT_ROUTING_DOMAIN = "Default";
    public static final String SKIP_VULENRABILITY = "skip";
    public static final String STATUS_QUEUEDGVM = "Queued";
    public static final String DUMMY_PASSWORD2 = "******";
    public static final String ADMIN_USERNAME = "admin";
    public static final String NOT_OK = "Not Ok";
    public static final String OK = "Ok";
    public static final String CIID_NONE = "none";
    public static final String CX_STATUS_FAILED = "Failed";
    public static final String NEXUS_STAGE_BUILD = "build";
    public static final String NEXUS_STAGE_SOURCE = "source";
    public static final String NPM = "npm";
    public static final String NEXUS_SEVERITY_SEVERE = "Severe";
    public static final String NEXUS_SEVERITY_MODERATE = "Moderate";
    public static final String VULNEARBILITY_SOURCE_IAC = "IaC";
    public static final String VULNERABILITY_HTTP_SERVER_DETECTED = "HTTP Server type and version";
}


