package io.mixeway.api.admin.controller;

import io.mixeway.api.admin.service.AdminScannerRestService;
import io.mixeway.api.protocol.rfw.RfwModel;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.utils.ScannerModel;
import io.mixeway.utils.Status;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

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

    /**
     * Endpoint which return list of all scanners added to DB
     *
     * @return list of defined scanners in DB
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Returning List of defined Scanners")
//    })
//    @ApiOperation(value = "Get Scanners",
//            notes = "Returning details of already created vulnerability scanners")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/scanners")
    public ResponseEntity<List<Scanner>> getScanners() {
        return adminScannerRestService.showScanners();
    }

    /**
     * Endpoint which return list of Scanner Types
     *
     * @return list of defined scanner types in DB
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Returning List of Scanner Types with defails of auth")
//    })
//    @ApiOperation(value = "Get Scanner Types",
//            notes = "Returning details of scanner types with name and auth info")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/scanertypes")
    public ResponseEntity<List<ScannerType>> getScannerTypes() {
        return adminScannerRestService.showScannerType();
    }

    /**
     * Endpoint save a new scanner
     *
     * @return status of operation
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 201, message = "Scanner created"),
//            @ApiResponse(code = 409, message = "Conflict - scanner cannot be added"),
//            @ApiResponse(code = 417, message = "Provided data are not correct, cannot test connectivity")
//    })
//    @ApiOperation(value = "Add new scanner",
//            notes = "Adding new scanner with given details")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/scanner/add")
    public ResponseEntity<Status> addScanner(@RequestBody ScannerModel scannerModel,
                                              Principal principal)  {
        return adminScannerRestService.addScanner(scannerModel, principal.getName());
    }

    /**
     * Endpoint delete scanner by id
     *
     * @return status of operation
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Deletion successful"),
//            @ApiResponse(code = 417, message = "Cannot delete scanner, unknown problem")
//    })
//    @ApiOperation(value = "Delete Scanner",
//            notes = "Delete scanner by ID")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @DeleteMapping(value = "/scanner/{id}")
    public ResponseEntity<Status> deleteScanner(@PathVariable("id")Long id,
                                                Principal principal)  {
        return adminScannerRestService.deleteScanner(id, principal.getName());
    }

    /**
     * Endpoint test a scanner by ID
     *
     * @return status of operation
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Test successful"),
//            @ApiResponse(code = 417, message = "Test failed")
//    })
//    @ApiOperation(value = "Test provided configuration",
//            notes = "Test if provided configuration is correct.")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/scanner/{id}/test")
    public ResponseEntity<Status> testScanner(@PathVariable("id")Long id,
                                              Principal principal)  {
        return adminScannerRestService.testScanner(id);
    }

    /**
     * Endpoint whicha add RFW configuration to scanner
     *
     * @return status of operation
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 201, message = "RFW Created"),
//            @ApiResponse(code = 417, message = "Problem with saving RFW")
//    })
//    @ApiOperation(value = "Add RFW configuration",
//            notes = "If RFW is enabled add configuration to it")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/scanner/{id}/addrfw")
    public ResponseEntity<Status> addRfw(@PathVariable("id")Long id,
                                         @RequestBody RfwModel rfwModel,
                                         Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return adminScannerRestService.addRfw(id, rfwModel, principal.getName());
    }

}
