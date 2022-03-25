package io.mixeway.api.admin.service;

import io.mixeway.api.protocol.rfw.RfwModel;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.domain.service.scanmanager.webapp.VerifyWebAppScannerService;
import io.mixeway.domain.service.scanner.DeleteScannerService;
import io.mixeway.domain.service.scanner.FindScannerService;
import io.mixeway.domain.service.scannertype.FindScannerTypeService;
import io.mixeway.scanmanager.integrations.remotefirewall.apiclient.RfwApiClient;
import io.mixeway.scanmanager.service.SecurityScanner;
import io.mixeway.utils.LogUtil;
import io.mixeway.utils.ScannerModel;
import io.mixeway.utils.Status;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.net.ProtocolException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@Log4j2
@RequiredArgsConstructor
public class AdminScannerRestService {
    private final VaultHelper vaultHelper;
    private final RfwApiClient rfwApiClient;
    private final List<SecurityScanner> securityScanners;
    private final VerifyWebAppScannerService verifyWebAppScannerService;
    private final FindScannerService findScannerService;
    private final FindScannerTypeService findScannerTypeService;
    private final DeleteScannerService deleteScannerService;


    public ResponseEntity<List<Scanner>> showScanners() {
        return new ResponseEntity<>(findScannerService.findAllScanners(), HttpStatus.OK);

    }
    public ResponseEntity<List<ScannerType>> showScannerType() {
        return new ResponseEntity<>(findScannerTypeService.findAll(), HttpStatus.OK);

    }
    public ResponseEntity<Status> addScanner(ScannerModel scannerModel, String name) {
        try {

            ScannerType scannerType = findScannerTypeService.findByName(scannerModel.getScannerType());
            if (verifyWebAppScannerService.canWebAppScannerBeAdded(scannerType)) {
                for (SecurityScanner securityScanner : securityScanners) {
                    if (securityScanner.canProcessRequest(scannerType)) {
                        Scanner scanner = securityScanner.saveScanner(scannerModel);
                        if (scanner != null)
                            securityScanner.initialize(scanner);
                    }
                }
                log.info("{} - Created new scanner of {} with apiurl {}", name, LogUtil.prepare(scannerModel.getScannerType()), LogUtil.prepare(scannerModel.getApiUrl()));
                return new ResponseEntity<>(new Status("not ok"), HttpStatus.CREATED);
            } else {
                log.info("There is WebApp Scan Policy set for {} cannot add scanner.", LogUtil.prepare(scannerModel.getApiUrl()));
                return new ResponseEntity<>(new Status("not ok"), HttpStatus.CONFLICT);
            }
        } catch(Exception e){
            e.printStackTrace();
            log.error("Cannot add scanner {} - {}",LogUtil.prepare(scannerModel.getApiUrl()), e.getLocalizedMessage());
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.PRECONDITION_FAILED);
        }
    }
    @Transactional
    public ResponseEntity<Status> deleteScanner(Long id, String name) {

        boolean removed = deleteScannerService.removeScanner(id);
        if (removed){
            log.info("{} - Deleted scanner id: {}", name, id);
            return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.PRECONDITION_FAILED);
        }
    }

    @Transactional
    public ResponseEntity<Status> testScanner(Long id) {
        Optional<Scanner> scanner = findScannerService.findById(id);
        try {
            if (scanner.isPresent()) {
                for (SecurityScanner securityScanner : securityScanners){
                    if (securityScanner.canProcessInitRequest(scanner.get())){
                        securityScanner.initialize(scanner.get());
                    }
                }
                return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
            } else {
                return new ResponseEntity<>(new Status("not ok"), HttpStatus.PRECONDITION_FAILED);
            }
        } catch (Exception e){
            log.error("Error during scanner testing {}", e.getLocalizedMessage());
            return new ResponseEntity<>(new Status(e.getLocalizedMessage()), HttpStatus.PRECONDITION_FAILED);
        }
    }

    @Transactional
    public ResponseEntity<Status> addRfw(Long id, RfwModel rfwModel, String name) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        try {
            Optional<Scanner> scanner = findScannerService.findById(id);
            if (scanner.isPresent()) {
                scanner.get().setRfwUrl(rfwModel.getRfwUrl());
                scanner.get().setRfwUser(rfwModel.getRfwUsername());
                scanner.get().setRfwScannerIp(rfwModel.getRfwScannerIp());
                String uuidToken = UUID.randomUUID().toString();
                if (vaultHelper.savePassword(rfwModel.getRfwPassword(), uuidToken)){
                    scanner.get().setRfwPassword(uuidToken);
                } else {
                    scanner.get().setRfwPassword(rfwModel.getRfwPassword());
                }
                log.info("{} - User added rfw for {} rules are {}", name, scanner.get().getApiUrl(), rfwApiClient.getListOfRules(scanner.get()));
                return new ResponseEntity<>(new Status("ok"), HttpStatus.CREATED);

            } else {
                return new ResponseEntity<>(new Status("not ok"), HttpStatus.PRECONDITION_FAILED);
            }
        } catch (ProtocolException pe ){
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.PRECONDITION_FAILED);
        }

    }


}
