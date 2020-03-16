package io.mixeway.rest.project.controller;

import io.mixeway.rest.project.model.RunScanForWebApps;
import io.mixeway.rest.project.model.WebAppCard;
import io.mixeway.rest.project.model.WebAppPutModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import io.mixeway.db.entity.WebAppVuln;
import io.mixeway.pojo.Status;
import io.mixeway.rest.project.service.WebAppService;

import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/v2/api/show/project")
public class WebAppController {
    private final WebAppService webAppService;

    @Autowired
    WebAppController(WebAppService webAppService){
        this.webAppService = webAppService;
    }


    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/webapps")
    public ResponseEntity<WebAppCard> showWebApps(@PathVariable("id")Long id, Principal principal) {
        return webAppService.showWebApps(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulns/webapp")
    public ResponseEntity<List<WebAppVuln>> showWebAppVulns(@PathVariable("id")Long id, Principal principal) {
        return webAppService.showWebAppVulns(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/add/webapp")
    public ResponseEntity<Status> saveWebApp(@PathVariable("id")Long id, @RequestBody WebAppPutModel webAppPutModel, Principal principal) {
        return webAppService.saveWebApp(id, webAppPutModel, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/webapp/webappautoscan")
    public ResponseEntity<Status> enableWebAppAutoScan(@PathVariable("id")Long id, Principal principal) {
        return webAppService.enableWebAppAutoScan(id, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/webapp/webappautoscan/disable")
    public ResponseEntity<Status> disableWebAppAutoScan(@PathVariable("id")Long id, Principal principal) {
        return webAppService.disableWebAppAutoScan(id, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/webapp/runall")
    public ResponseEntity<Status> runAllScanForWebApp(@PathVariable("id")Long id, Principal principal) {
        return webAppService.runAllScanForWebApp(id, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/webapp/runselected")
    public ResponseEntity<Status> runSelectedWebApps(@PathVariable("id")Long id, @RequestBody List<RunScanForWebApps> runScanForWebApps, Principal principal) {
        return webAppService.runSelectedWebApps(id, runScanForWebApps, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/webapp/{webAppId}/run")
    public ResponseEntity<Status> runSingleWebApp(@PathVariable("webAppId") Long webAppId, Principal principal) {
        return webAppService.runSingleWebApp(webAppId,principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @DeleteMapping(value = "/webapp/{webAppId}")
    public ResponseEntity<Status> deleteWebApp(@PathVariable("webAppId") Long webAppId, Principal principal) {
        return webAppService.deleteWebApp(webAppId, principal.getName());
    }

}
