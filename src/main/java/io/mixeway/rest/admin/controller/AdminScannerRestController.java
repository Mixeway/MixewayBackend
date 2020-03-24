package io.mixeway.rest.admin.controller;

import io.mixeway.db.entity.Scanner;
import io.mixeway.rest.model.RfwModel;
import io.mixeway.rest.model.ScannerModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.pojo.Status;
import io.mixeway.rest.admin.service.AdminScannerRestService;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;

@Controller
@RequestMapping("/v2/api/admin")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AdminScannerRestController {
    private final AdminScannerRestService adminScannerRestService;

    AdminScannerRestController(AdminScannerRestService adminScannerRestService){
        this.adminScannerRestService = adminScannerRestService;
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/scanners")
    public ResponseEntity<List<Scanner>> showScanners() {
        return adminScannerRestService.showScanners();
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/scanertypes")
    public ResponseEntity<List<ScannerType>> getScannerTypes() {
        return adminScannerRestService.showScannerType();
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/scanner/add")
    public ResponseEntity<Status> addScanner(@RequestBody ScannerModel scannerModel, Principal principal)  {
        return adminScannerRestService.addScanner(scannerModel, principal.getName());
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @DeleteMapping(value = "/scanner/{id}")
    public ResponseEntity<Status> deleteScanner(@PathVariable("id")Long id, Principal principal)  {
        return adminScannerRestService.deleteScanner(id, principal.getName());
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/scanner/{id}/test")
    public ResponseEntity<Status> testScanner(@PathVariable("id")Long id, Principal principal)  {
        return adminScannerRestService.testScanner(id);
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/scanner/{id}/addrfw")
    public ResponseEntity<Status> addRfw(@PathVariable("id")Long id, @RequestBody RfwModel rfwModel, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return adminScannerRestService.addRfw(id, rfwModel, principal.getName());
    }

}
