package io.mixeway.rest.project.controller;

import io.mixeway.plugins.opensourcescan.model.Projects;
import io.mixeway.rest.project.model.*;
import org.codehaus.jettison.json.JSONException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeVuln;
import io.mixeway.pojo.Status;
import io.mixeway.rest.project.service.CodeService;

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
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/codegroups")
    public ResponseEntity<List<CodeGroup>> showCodeGroups(@PathVariable("id")Long id, Principal principal) {
        return codeService.showCodeGroups(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/add/codegroup")
    public ResponseEntity<Status> saveCodeGroup(@PathVariable("id")Long id, @RequestBody CodeGroupPutModel codeGroupPutModel, Principal principal) {
        return codeService.saveCodeGroup(id, codeGroupPutModel, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/add/codeproject")
    public ResponseEntity<Status> saveCodeProject(@PathVariable("id")Long id, @RequestBody CodeProjectPutModel codeProjectPutModel, Principal principal) {
        return codeService.saveCodeProject(id, codeProjectPutModel, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/codeproject/runselected")
    public ResponseEntity<Status> runSelectedCodeProjects(@PathVariable("id")Long id, @RequestBody List<RunScanForCodeProject> runScanForCodeProjects, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeService.runSelectedCodeProjects(id, runScanForCodeProjects, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/code/enableautoscan")
    public ResponseEntity<Status> enableAutoScanForCodeProjects(@PathVariable("id")Long id, Principal principal) {
        return codeService.enableAutoScanForCodeProjects(id, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/code/disableautoscan")
    public ResponseEntity<Status> disableAutoScanForCodeProjects(@PathVariable("id")Long id, Principal principal) {
        return codeService.disableAutoScanForCodeProjects(id, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/codeproject/{codeProjectId}/run")
    public ResponseEntity<Status> runSingleCodeProjectScan(@PathVariable("codeProjectId")Long codeProjectId, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeService.runSingleCodeProjectScan(codeProjectId,principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @DeleteMapping(value = "/codeproject/{codeProjectId}")
    public ResponseEntity<Status> deletecodeProject(@PathVariable("codeProjectId")Long codeProjectId, Principal principal) {
        return codeService.deleteCodeProject(codeProjectId,principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulns/code")
    public ResponseEntity<List<CodeVuln>> showCodeVulns(@PathVariable("id")Long id, Principal principal) {
        return codeService.showCodeVulns(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PatchMapping(value = "/codeproject/{id}")
    public ResponseEntity<Status> editCodeProject(@PathVariable("id")Long id, @RequestBody EditCodeProjectModel editCodeProjectModel, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeService.editCodeProject(id, editCodeProjectModel, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/codeproject/{id}/createdtrack")
    public ResponseEntity<Status> createDTrackProject(@PathVariable("id")Long id, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeService.createDTrackProject(id, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/dtrackprojects")
    public ResponseEntity<List<Projects>> getdTracksProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeService.getdTracksProjects();
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/codeprojects")
    public ResponseEntity<List<SASTProject>> getCodeProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
        return codeService.getCodeProjects();
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{projectId}/createremoteproject/{id}")
    public ResponseEntity<Status> createRemoteProject(@PathVariable("id")Long id,@PathVariable("projectId")Long projectId) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
        return codeService.createRemoteProject(id, projectId);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{projectId}/opensource/{codeGroup}/{codeProject}")
    public ResponseEntity<OpenSourceConfig> getOpenSourceConfig(@PathVariable("projectId")Long id,@PathVariable("codeGroup")String codeGroup,
                                                                @PathVariable("codeProject")String codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
        return codeService.getOpenSourceConfig(id, codeGroup, codeProject);
    }
}
