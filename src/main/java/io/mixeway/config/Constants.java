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
	public static final int ACUNETIX_TARGET_LIMIT = 25;
	public static final String ACUNETIX_PAGINATION = "pagination";
	public static final String ACUNETIX_NETX_CURSOR = "next_cursor";
	public static final String ACUNETIX_IMPACT = "impact";
	public static final String ACUNETIX_REQUEST = "request";
	
	// API TYPES
	public static final String API_TYPE_CIS_K8S = "cis-k8s";
	public static final String API_SCANNER_OPENVAS = "networkScanner";
	public static final String API_SCANNER_WEBAPP = "webApplicationScanner";
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

    public static final String JIRA = "Jira";
}
