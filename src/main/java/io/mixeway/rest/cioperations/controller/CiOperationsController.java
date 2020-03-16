package io.mixeway.rest.cioperations.controller;

import io.mixeway.rest.cioperations.model.CiResultModel;
import io.mixeway.rest.cioperations.service.CiOperationsService;
import io.mixeway.rest.model.OverAllVulnTrendChartData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.mixeway.db.entity.CiOperations;

import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/v2/api/cicd")
public class CiOperationsController {
    private final CiOperationsService ciOperationsService;

    @Autowired
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
}
