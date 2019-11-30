package io.mixeway.rest.project.controller;

import io.mixeway.rest.project.model.AssetCard;
import io.mixeway.rest.project.model.AssetPutModel;
import io.mixeway.rest.project.model.RunScanForAssets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import io.mixeway.db.entity.InfrastructureVuln;
import io.mixeway.pojo.Status;
import io.mixeway.rest.project.service.AssetService;

import javax.validation.Valid;
import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/v2/api/show/project")
public class AssetControler {
    private final AssetService assetService;

    @Autowired
    AssetControler(AssetService assetService){
        this.assetService = assetService;
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/assets")
    public ResponseEntity<AssetCard> showAssets(@PathVariable("id")Long id) {
        return assetService.showAssets(id);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/asset/add")
    public ResponseEntity<Status> saveAsset(@PathVariable("id")Long id, @Valid @RequestBody AssetPutModel assetPutModel, Principal principal) {
        return assetService.saveAsset(id, assetPutModel, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/asset/runselected")
    public ResponseEntity<Status> runScanForAssets(@PathVariable("id")Long id, @RequestBody List<RunScanForAssets> runScanForAssets, Principal principal) {
        return assetService.runScanForAssets(id, runScanForAssets, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/asset/runall")
    public ResponseEntity<Status> runAllAssetScan(@PathVariable("id")Long id, Principal principal) {
        return assetService.runAllAssetScan(id, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/asset/{assetId}/runsingle")
    public ResponseEntity<Status> runSingleAssetScan( @PathVariable("assetId") Long assetId, Principal principal) {
        return assetService.runSingleAssetScan(assetId, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @DeleteMapping(value = "/asset/{assetId}")
    public ResponseEntity<Status> deleteAsset( @PathVariable("assetId") Long assetId, Principal principal) {
        return assetService.deleteAsset(assetId, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulns/infra")
    public ResponseEntity<List<InfrastructureVuln>> showInfraVulns(@PathVariable("id")Long id) {
        return assetService.showInfraVulns(id);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/asset/infraautoscan")
    public ResponseEntity<Status> enableInfraAutoScan(@PathVariable("id")Long id, Principal principal) {
        return assetService.enableInfraAutoScan(id, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/asset/infraautoscan/disable")
    public ResponseEntity<Status> disableInfraAutoScan(@PathVariable("id")Long id, Principal principal) {
        return assetService.disableInfraAutoScan(id, principal.getName());
    }

}
