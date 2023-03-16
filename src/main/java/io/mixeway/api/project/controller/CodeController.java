package io.mixeway.api.project.controller;

import io.mixeway.api.project.model.CodeCard;
import io.mixeway.api.project.model.CodeProjectPutModel;
import io.mixeway.api.project.model.CodeProjectSearch;
import io.mixeway.api.project.model.EditCodeProjectModel;
import io.mixeway.api.project.service.CodeService;
import io.mixeway.api.protocol.OpenSourceConfig;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.scanmanager.model.Projects;
import io.mixeway.utils.RunScanForCodeProject;
import io.mixeway.utils.SASTProject;
import io.mixeway.utils.Status;
import org.codehaus.jettison.json.JSONException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.List;

@Controller
@RequestMapping("/v2/api/show/project")
public class CodeController {
    private final CodeService codeService;

    CodeController(CodeService codeService){
        this.codeService = codeService;
    }


    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/codes")
    public ResponseEntity<CodeCard> showCodeRepos(@PathVariable("id")Long id, Principal principal) {
        return codeService.showCodeRepos(id, principal);
    }

    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/add/codeproject")
    public ResponseEntity<Status> saveCodeProject(@PathVariable("id")Long id, @RequestBody CodeProjectPutModel codeProjectPutModel, Principal principal) {
        return codeService.saveCodeProject(id, codeProjectPutModel, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/codeproject/runselected")
    public ResponseEntity<Status> runSelectedCodeProjects(@PathVariable("id")Long id, @RequestBody List<RunScanForCodeProject> runScanForCodeProjects, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeService.runSelectedCodeProjects(id, runScanForCodeProjects, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/code/enableautoscan")
    public ResponseEntity<Status> enableAutoScanForCodeProjects(@PathVariable("id")Long id, Principal principal) {
        return codeService.enableAutoScanForCodeProjects(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/code/disableautoscan")
    public ResponseEntity<Status> disableAutoScanForCodeProjects(@PathVariable("id")Long id, Principal principal) {
        return codeService.disableAutoScanForCodeProjects(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/codeproject/{codeProjectId}/run")
    public ResponseEntity<Status> runSingleCodeProjectScan(@PathVariable("codeProjectId")Long codeProjectId, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeService.runSingleCodeProjectScan(codeProjectId,principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @DeleteMapping(value = "/codeproject/{codeProjectId}")
    public ResponseEntity<Status> deletecodeProject(@PathVariable("codeProjectId")Long codeProjectId, Principal principal) {
        return codeService.deleteCodeProject(codeProjectId,principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulns/code")
    public ResponseEntity<List<ProjectVulnerability>> showCodeVulns(@PathVariable("id")Long id, Principal principal) {
        return codeService.showCodeVulns(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PatchMapping(value = "/codeproject/{id}")
    public ResponseEntity<Status> editCodeProject(@PathVariable("id")Long id, @RequestBody EditCodeProjectModel editCodeProjectModel, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeService.editCodeProject(id, editCodeProjectModel, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/codeproject/{id}/createdtrack")
    public ResponseEntity<Status> createDTrackProject(@PathVariable("id")Long id, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeService.createDTrackProject(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/opensourceprojects")
    public ResponseEntity<List<Projects>> getOpenSourceProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeService.getOpenSourceProjects();
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/codeprojects")
    public ResponseEntity<List<SASTProject>> getCodeProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
        return codeService.getCodeProjects();
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{projectId}/createremoteproject/{id}")
    public ResponseEntity<Status> createRemoteProject(@PathVariable("id")Long id,@PathVariable("projectId")Long projectId, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
        return codeService.createRemoteProject(id, projectId, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{projectId}/opensource/{codeGroup}/{codeProject}")
    public ResponseEntity<OpenSourceConfig> getOpenSourceConfig(@PathVariable("projectId")Long id, @PathVariable("codeGroup")String codeGroup,
                                                                @PathVariable("codeProject")String codeProject,
                                                                Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
        return codeService.getOpenSourceConfig(id, codeGroup, codeProject, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @PostMapping(value = "/code/details")
    public ResponseEntity<CodeProject> searchCodeDetailsByRepoUrl(@RequestBody CodeProjectSearch search, Principal principal) {
        return codeService.searchCodeProject(search, principal);
    }
}
