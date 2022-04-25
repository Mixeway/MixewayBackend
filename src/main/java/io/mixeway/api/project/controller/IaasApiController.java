package io.mixeway.api.project.controller;

import io.mixeway.api.project.model.IaasApiPutModel;
import io.mixeway.api.project.model.IaasModel;
import io.mixeway.api.project.service.IaasApiService;
import io.mixeway.db.entity.IaasApiType;
import io.mixeway.utils.Status;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/v2/api/show/project")
public class IaasApiController {
    private final IaasApiService iaasApiService;

    IaasApiController(IaasApiService iaasApiService){
        this.iaasApiService = iaasApiService;
    }

    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/{id}/iaasapi")
    public ResponseEntity<IaasModel> showIaasApi(@PathVariable("id")Long id, Principal principal) {
        return iaasApiService.showIaasApi(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/add/iaasapi")
    public ResponseEntity<Status> saveIaasApi(@PathVariable("id")Long id, @Valid @RequestBody IaasApiPutModel iaasApiPutModel, Principal principal) {
        return iaasApiService.saveIaasApi(id, iaasApiPutModel,principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/{id}/iaasapi/test")
    public ResponseEntity<Status> testIaasApi(@PathVariable("id")Long id, Principal principal) {
        return iaasApiService.testIaasApi(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/{id}/iaasapi/enable")
    public ResponseEntity<Status> iaasApiEnableSynchro(@PathVariable("id")Long id, Principal principal) {
        return iaasApiService.iaasApiEnableSynchro(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/{id}/iaasapi/disable")
    public ResponseEntity<Status> iaasApiDisableSynchro(@PathVariable("id")Long id, Principal principal) {
        return iaasApiService.iaasApiDisableSynchro(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @DeleteMapping(value = "/{id}/iaasapi")
    public ResponseEntity<Status> iaasApiDelete(@PathVariable("id")Long id, Principal principal) {
        return iaasApiService.iaasApiDelete(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/iaasapitype")
    public ResponseEntity<List<IaasApiType>> getIaasApiTypes(Principal principal) {
        return iaasApiService.getIaasApiTypes(principal);
    }

}
