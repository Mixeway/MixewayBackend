package io.mixeway.scanmanager.integrations.vulnauditor.apiclient;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.entity.VulnerabilitySource;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.vulnauditor.model.VulnAuditorRequest;
import io.mixeway.scanmanager.integrations.vulnauditor.model.VulnAuditorRequestModel;
import io.mixeway.scanmanager.integrations.vulnauditor.model.VulnAuditorResponse;
import io.mixeway.utils.SecureRestTemplate;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
@Component
public class MixewayVulnAuditorApiClient {
    private final static Logger log = LoggerFactory.getLogger(MixewayVulnAuditorApiClient.class);
    private final SecureRestTemplate secureRestTemplate;
    private final VulnTemplate vulnTemplate;

    public MixewayVulnAuditorApiClient(SecureRestTemplate secureRestTemplate, VulnTemplate vulnTemplate){
        this.secureRestTemplate = secureRestTemplate;
        this.vulnTemplate = vulnTemplate;
    }

    /**
     * Method which is calling Mixeway Vuln Auditor API in order to perdict classification of given Vulnerability List
     *
     * @param projectVulnerability
     * @param vulnAuditorUrl
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws KeyManagementException
     */
    public void perdict(List<ProjectVulnerability> projectVulnerability, String vulnAuditorUrl) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(null);
        VulnAuditorRequestModel vulnAuditorRequestModel = prepareRequestModel(projectVulnerability);
        HttpEntity<List<VulnAuditorRequest>> entity = new HttpEntity<>(vulnAuditorRequestModel.getVulnAuditorRequests());
        System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2");
        ResponseEntity<VulnAuditorResponse[]> response = restTemplate.exchange(vulnAuditorUrl +
                "/vuln/perdict", HttpMethod.POST, entity, VulnAuditorResponse[].class);
        List<ProjectVulnerability> projectVulnerabilities = new ArrayList<>();
        if (response.getStatusCode().equals(HttpStatus.OK)){
            for (VulnAuditorResponse vulnAuditorResponse : response.getBody()){
                ProjectVulnerability vulnerability = vulnTemplate.projectVulnerabilityRepository.getOne(vulnAuditorResponse.getId());
                vulnerability.setGrade(vulnAuditorResponse.getAudit());
                vulnTemplate.projectVulnerabilityRepository.save(vulnerability);
                projectVulnerabilities.add(vulnerability);
            }
        }
        log.info("Successfully loaded perdicted classification for {} Vulnerabilities Pojects({})  sources({})", response.getBody().length,
                projectVulnerabilities
                        .stream()
                        .map(ProjectVulnerability::getProject)
                        .distinct()
                        .collect(Collectors.toList())
                        .stream()
                        .map(Project::getName)
                        .collect(Collectors.joining(",")),
                projectVulnerabilities.stream().map(ProjectVulnerability::getVulnerabilitySource)
                .map(VulnerabilitySource::getName).distinct()
                .collect(Collectors.joining(","))
        );
    }

    /**
     * Maps Project Vulnerability into VulnAuditorRequestModel DTO
     *
     * @param projectVulnerability
     * @return
     */
    private VulnAuditorRequestModel prepareRequestModel(List<ProjectVulnerability> projectVulnerability) {
        List<VulnAuditorRequest>vulnAuditorRequests = new ArrayList<>();
        for (ProjectVulnerability pv : projectVulnerability){
            String description, severity, vulnName, appName = null, appContext = null;
            description = StringUtils.isNotBlank(pv.getDescription()) ? pv.getDescription() : "empty";
            severity = pv.getSeverity();
            vulnName = pv.getVulnerability().getName();
            if (pv.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_SOURCECODE)){
                appName = pv.getCodeProject().getName();
                String client = (StringUtils.isNotBlank(pv.getCodeProject().getAppClient())? pv.getCodeProject().getAppClient():
                        (StringUtils.isNotBlank(pv.getProject().getAppClient())? pv.getProject().getAppClient() : "empty") );
                appContext = "type sourceode client " + client;
            } else  if (pv.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_NETWORK)) {
                appName = pv.getLocation();
                appContext = "type network location " + (StringUtils.isNotBlank(pv.getProject().getNetworkdc())? pv.getProject().getNetworkdc() : "empty")+" domain "+ pv.getAnInterface().getRoutingDomain().getName();
            } else if (pv.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_WEBAPP)){
                appName = pv.getLocation();
                String routingDomainName = pv.getWebApp().getRoutingDomain()!=null? pv.getWebApp().getRoutingDomain().getName() : Constants.DOMAIN_INTERNET;
                String appClient = (StringUtils.isNotBlank(pv.getProject().getAppClient()) ? pv.getProject().getAppClient() : "empty");
                appContext = "type webapp client "+ appClient + " domain "+routingDomainName;
            } else if (pv.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_OPENSOURCE)){
                appName = pv.getCodeProject().getName();
                appContext = "type opensource";
            } else {
                log.error("Trying to perdict vulnerability of unknown source - {}, breaking", pv.getVulnerabilitySource().getName());
                break;
            }
            vulnAuditorRequests.add(new VulnAuditorRequest(pv.getId(),appName,appContext,vulnName, description, severity));
        }
        return new VulnAuditorRequestModel(vulnAuditorRequests);
    }
}
