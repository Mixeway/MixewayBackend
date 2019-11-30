package io.mixeway.rest.project.controller;

import io.mixeway.rest.project.model.CodeCard;
import io.mixeway.rest.project.model.CodeGroupPutModel;
import io.mixeway.rest.project.model.CodeProjectPutModel;
import io.mixeway.rest.project.model.RunScanForCodeProject;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.List;

@Controller
@RequestMapping("/v2/api/show/project")
public class CodeController {
    private final CodeService codeService;

    @Autowired
    CodeController(CodeService codeService){
        this.codeService = codeService;
    }


    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/codes")
    public ResponseEntity<CodeCard> showCodeRepos(@PathVariable("id")Long id) {
        return codeService.showCodeRepos(id);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/codegroups")
    public ResponseEntity<List<CodeGroup>> showCodeGroups(@PathVariable("id")Long id) {
        return codeService.showCodeGroups(id);
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
    public ResponseEntity<List<CodeVuln>> showCodeVulns(@PathVariable("id")Long id) {
        return codeService.showCodeVulns(id);
    }
}
