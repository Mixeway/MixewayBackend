package io.mixeway.rest.cioperations.controller;

import io.mixeway.pojo.CIVulnManageResponse;
import io.mixeway.pojo.Status;
import io.mixeway.rest.cioperations.model.*;
import io.mixeway.rest.cioperations.service.CiOperationsService;
import io.mixeway.rest.model.OverAllVulnTrendChartData;
import org.codehaus.jettison.json.JSONException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import io.mixeway.db.entity.CiOperations;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.List;

@RestController
@RequestMapping("/v2/api/cicd")
public class CiOperationsController {
    private final CiOperationsService ciOperationsService;

    CiOperationsController(CiOperationsService ciOperationsService){
        this.ciOperationsService = ciOperationsService;
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/trend")
    public ResponseEntity<List<OverAllVulnTrendChartData>> getVulnTrendData(Principal principal)  {
        return ciOperationsService.getVulnTrendData(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/result")
    public ResponseEntity<CiResultModel> getResponseData(Principal principal) {
        return ciOperationsService.getResultData(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/data")
    public ResponseEntity<List<CiOperations>> getTableData(Principal principal)  {
        return ciOperationsService.getTableData(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/data/project/{id}")
    public ResponseEntity<List<CiOperations>> getTableDataForProject(Principal principal, @PathVariable("id") Long id)  {
        return ciOperationsService.getTableDataForProject(principal, id);
    }

    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value = "/project/{id}/code/init/{groupName}/{projectName}/{commitId}")
    public ResponseEntity<Status> startpipeline(@PathVariable("id") long projectId, @PathVariable("groupName") String groupName,
                                                @PathVariable("projectName") String codeProjectName,
                                                @PathVariable("commitId") String commitId,
                                                Principal principal)  {
        return ciOperationsService.startPipeline(projectId,groupName,codeProjectName,commitId, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @RequestMapping(value = "/project/{projectId}/code/scan/{groupName}/{projectName}/{commitId}", method = RequestMethod.PUT,produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Status> codeScan(@PathVariable(value = "projectId") Long id,
                                                                       @PathVariable(value="groupName") String groupName,
                                                                       @PathVariable(value="projectName") String projectName,
                                                                       @PathVariable("commitId") String commitId,
                                           Principal principal) throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, JSONException, ParseException {
        return ciOperationsService.codeScan(id,groupName,projectName,commitId, principal);
    }
    @CrossOrigin(origins="*")
    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value = "/project/{projectId}/code/verify/{codeGroup}/{codeProject}/{commitid}",produces = "application/json")
    public ResponseEntity<CIVulnManageResponse> codeVerify(@PathVariable(value = "codeGroup") String codeGroup,
                                                                   @PathVariable(value = "codeProject") String codeProject,
                                                                   @PathVariable(value = "projectId") Long id,
                                                                    @PathVariable("commitid") String commitid,
                                                           Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return ciOperationsService.codeVerify(codeGroup, codeProject, id, commitid, principal);
    }


    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/getscannerinfo",produces = "application/json")
    public ResponseEntity<PrepareCIOperation> getInfoForCI(@Valid @RequestBody GetInfoRequest getInfoRequest, Principal principal) throws Exception {
        return ciOperationsService.getInfoForCI(getInfoRequest, principal);
    }

    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/infoscanperformed",produces = "application/json")
    public ResponseEntity<Status> infoScanPerformed(@RequestBody InfoScanPerformed infoScanPerformed, Principal principal) throws Exception {
        return ciOperationsService.infoScanPerformed(infoScanPerformed,principal);
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/loadvulnerabilities/{projectId}/{codeProjectName}/{branch}/{commitId}",produces = "application/json")
    public ResponseEntity<Status> loadVulnerabilitiesFromCICDToProject(@RequestBody List<VulnerabilityModel> vulns, @PathVariable(value = "projectId") Long projectId,
                                                                       @PathVariable(value = "codeProjectName") String codeProjectName,
                                                                       @PathVariable(value = "branch") String branch,
                                                                       @PathVariable(value = "commitId") String commitId, Principal principal) throws Exception {
        return ciOperationsService.loadVulnerabilitiesFromCICDToProject(vulns, projectId, codeProjectName, branch, commitId, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/loadvulnerabilities/{codeProjectName}/{branch}/{commitId}",produces = "application/json")
    public ResponseEntity<Status> loadVulnerabilitiesFromCICD(@RequestBody List<VulnerabilityModel> vulns,
                                                                       @PathVariable(value = "codeProjectName") String codeProjectName,
                                                                       @PathVariable(value = "branch") String branch,
                                                                       @PathVariable(value = "commitId") String commitId, Principal principal) throws Exception {
        return ciOperationsService.loadVulnerabilitiesFromCICDToProject(vulns, null, codeProjectName, branch, commitId, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value="/loadvulnerabilities/{codeProjectName}")
    public ResponseEntity<Status> loadVulnerabilitiesForAnonymousProject (@RequestBody List<VulnerabilityModel> vulns,
                                                                          @PathVariable(value = "codeProjectName") String codeProjectName,
                                                                          Principal principal) {
        return ciOperationsService.loadVulnerabilitiesForAnonymousProject(vulns, codeProjectName,principal);
    }

}
