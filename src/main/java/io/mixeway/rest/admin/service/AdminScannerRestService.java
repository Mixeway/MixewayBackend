package io.mixeway.rest.admin.service;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.ProxiesRepository;
import io.mixeway.db.repository.RoutingDomainRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.plugins.remotefirewall.apiclient.RfwApiClient;
import io.mixeway.pojo.SecurityScanner;
import io.mixeway.rest.model.RfwModel;
import io.mixeway.rest.model.ScannerModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.pojo.Status;

import java.io.IOException;
import java.net.ProtocolException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.*;

@Service
public class AdminScannerRestService {
    private static final Logger log = LoggerFactory.getLogger(AdminScannerRestService.class);
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final ProxiesRepository proxiesRepository;
    private final VaultOperations operations;
    private final RfwApiClient rfwApiClient;
    private final RoutingDomainRepository routingDomainRepository;
    private final List<SecurityScanner> securityScanners;
    @Autowired
    AdminScannerRestService(RoutingDomainRepository routingDomainRepository, List<SecurityScanner> securityScanners,
                            RfwApiClient rfwApiClient, VaultOperations vaultOperations,
                            ProxiesRepository proxiesRepository, ScannerTypeRepository scannerTypeRepository, ScannerRepository scannerRepository){
        this.routingDomainRepository = routingDomainRepository;
        this.rfwApiClient = rfwApiClient;
        this.operations = vaultOperations;
        this.proxiesRepository = proxiesRepository;
        this.securityScanners = securityScanners;
        this.scannerRepository = scannerRepository;
        this.scannerTypeRepository = scannerTypeRepository;
    }

    public ResponseEntity<List<io.mixeway.db.entity.Scanner>> showScanners() {
        return new ResponseEntity<>(scannerRepository.findAll(), HttpStatus.OK);

    }
    public ResponseEntity<List<ScannerType>> showScannerType() {
        return new ResponseEntity<>(scannerTypeRepository.findAll(), HttpStatus.OK);

    }
    public ResponseEntity<Status> addScanner(ScannerModel scannerModel, String name) {
        try {

            ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
            for (SecurityScanner securityScanner : securityScanners){
                if (securityScanner.canProcessRequest(scannerType)){
                    securityScanner.saveScanner(scannerModel);
                }
            }
           log.info("{} - Created new scanner of {} with apiurl {}", name, scannerModel.getScannerType(), scannerModel.getApiUrl());
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.CREATED);
        } catch(Exception e){
            e.printStackTrace();
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.PRECONDITION_FAILED);
        }
    }

    public ResponseEntity<Status> deleteScanner(Long id, String name) {
        Optional<io.mixeway.db.entity.Scanner> scanner = scannerRepository.findById(id);
        if (scanner.isPresent()){
            scannerRepository.delete(scanner.get());
            log.info("{} - Deleted scanner {}", name, scanner.get().getApiUrl());
            return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.PRECONDITION_FAILED);
        }
    }

    public ResponseEntity<Status> testScanner(Long id) {
        Optional<io.mixeway.db.entity.Scanner> scanner = scannerRepository.getById(id);
        try {
            if (scanner.isPresent()) {
                for (SecurityScanner securityScanner : securityScanners){
                    if (securityScanner.canProcessRequest(scanner.get())){
                        securityScanner.initialize(scanner.get());
                    }
                }
                return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
            } else {
                return new ResponseEntity<>(new Status("not ok"), HttpStatus.PRECONDITION_FAILED);
            }
        } catch (Exception e){
            e.printStackTrace();
            return new ResponseEntity<>(new Status(e.getLocalizedMessage()), HttpStatus.PRECONDITION_FAILED);
        }
    }

    public ResponseEntity<Status> addRfw(Long id, RfwModel rfwModel, String name) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        try {
            Optional<Scanner> scanner = scannerRepository.findById(id);
            if (scanner.isPresent()) {
                scanner.get().setRfwUrl(rfwModel.getRfwUrl());
                scanner.get().setRfwUser(rfwModel.getRfwUsername());
                scanner.get().setRfwScannerIp(rfwModel.getRfwScannerIp());
                scanner.get().setRfwPassword(UUID.randomUUID().toString());
                Map<String, String> upassMap = new HashMap<>();
                upassMap.put("password", rfwModel.getRfwPassword());
                operations.write("secret/" + scanner.get().getRfwPassword(), upassMap);
                log.info("{} - User added rfw for {} rules are {}", name, scanner.get().getApiUrl(), rfwApiClient.getListOfRules(scanner.get()));
                scannerRepository.save(scanner.get());
                return new ResponseEntity<>(new Status("ok"), HttpStatus.CREATED);

            } else {
                return new ResponseEntity<>(new Status("not ok"), HttpStatus.PRECONDITION_FAILED);
            }
        } catch (ProtocolException pe ){
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.PRECONDITION_FAILED);
        }

    }


}
