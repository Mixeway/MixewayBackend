package io.mixeway.api.project.controller;

import io.mixeway.api.project.model.AssetCard;
import io.mixeway.api.project.model.AssetPutModel;
import io.mixeway.api.project.service.AssetService;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.utils.RunScanForAssets;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/v2/api/show/project")
@RequiredArgsConstructor
public class AssetControler {
    private final AssetService assetService;


    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/assets")
    public ResponseEntity<AssetCard> showAssets(Principal principal, @PathVariable("id")Long id) {
        return assetService.showAssets(id,principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/asset/add")
    public ResponseEntity<Status> saveAsset(@PathVariable("id")Long id, @Valid @RequestBody AssetPutModel assetPutModel, Principal principal) {
        return assetService.saveAsset(id, assetPutModel, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/asset/runselected")
    public ResponseEntity<Status> runScanForAssets(@PathVariable("id")Long id, @RequestBody List<RunScanForAssets> runScanForAssets, Principal principal) throws Exception {
        return assetService.runScanForAssets(id, runScanForAssets, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/asset/runall")
    public ResponseEntity<Status> runAllAssetScan(@PathVariable("id")Long id, Principal principal) throws Exception {
        return assetService.runAllAssetScan(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/asset/{assetId}/runsingle")
    public ResponseEntity<Status> runSingleAssetScan( @PathVariable("assetId") Long assetId, Principal principal) throws Exception {
        return assetService.runSingleAssetScan(assetId, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @DeleteMapping(value = "/asset/{assetId}")
    public ResponseEntity<Status> deleteAsset( @PathVariable("assetId") Long assetId, Principal principal) {
        return assetService.deleteAsset(assetId, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulns/infra")
    public ResponseEntity<List<ProjectVulnerability>> showInfraVulns(Principal principal, @PathVariable("id")Long id) {
        return assetService.showInfraVulns(id,principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/asset/infraautoscan")
    public ResponseEntity<Status> enableInfraAutoScan(@PathVariable("id")Long id, Principal principal) {
        return assetService.enableInfraAutoScan(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/asset/infraautoscan/disable")
    public ResponseEntity<Status> disableInfraAutoScan(@PathVariable("id")Long id, Principal principal) {
        return assetService.disableInfraAutoScan(id, principal);
    }

}
