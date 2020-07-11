package io.mixeway.rest.project.controller;

import io.mixeway.db.entity.IaasApiType;
import io.mixeway.rest.project.model.IaasApiPutModel;
import io.mixeway.rest.project.model.IaasModel;
import org.codehaus.jettison.json.JSONException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import io.mixeway.pojo.Status;
import io.mixeway.rest.project.service.IaasApiService;

import javax.validation.Valid;
import java.security.Principal;
import java.text.ParseException;
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
    public ResponseEntity<IaasModel> showIaasApi(@PathVariable("id")Long id) {
        return iaasApiService.showIaasApi(id);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/add/iaasapi")
    public ResponseEntity<Status> saveIaasApi(@PathVariable("id")Long id, @Valid @RequestBody IaasApiPutModel iaasApiPutModel, Principal principal) {
        return iaasApiService.saveIaasApi(id, iaasApiPutModel,principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/{id}/iaasapi/test")
    public ResponseEntity<Status> testIaasApi(@PathVariable("id")Long id) {
        return iaasApiService.testIaasApi(id);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/{id}/iaasapi/enable")
    public ResponseEntity<Status> iaasApiEnableSynchro(@PathVariable("id")Long id, Principal principal) {
        return iaasApiService.iaasApiEnableSynchro(id, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/{id}/iaasapi/disable")
    public ResponseEntity<Status> iaasApiDisableSynchro(@PathVariable("id")Long id, Principal principal) {
        return iaasApiService.iaasApiDisableSynchro(id, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @DeleteMapping(value = "/{id}/iaasapi")
    public ResponseEntity<Status> iaasApiDelete(@PathVariable("id")Long id, Principal principal) {
        return iaasApiService.iaasApiDelete(id, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/iaasapitype")
    public ResponseEntity<List<IaasApiType>> getIaasApiTypes(Principal principal) {
        return iaasApiService.getIaasApiTypes(principal.getName());
    }

}
