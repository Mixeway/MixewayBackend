package io.mixeway.api.admin.service;

import io.mixeway.api.protocol.rfw.RfwModel;
import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.acunetix.apiclient.AcunetixApiClient;
import io.mixeway.scanmanager.integrations.remotefirewall.apiclient.RfwApiClient;
import io.mixeway.scanmanager.service.SecurityScanner;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.utils.ScannerModel;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AdminScannerRestServiceTest {
    private final AdminScannerRestService adminScannerRestService;
    private final UserRepository userRepository;
    private final ScannerRepository scannerRepository;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final ScannerTypeRepository scannerTypeRepository;

    @Mock
    Principal principal;
    @MockBean
    AcunetixApiClient acunetixApiClient;
    @MockBean
    RfwApiClient rfwApiClient;

    @MockBean
    GlobalScheduler globalScheduler;

    @MockBean
    NetworkScanScheduler networkScheduler;

    @MockBean
    CodeScheduler codeScheduler;

    @MockBean
    WebAppScheduler webAppScheduler;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("admin_scanner");
        User userToCreate = new User();
        userToCreate.setUsername("admin_scanner");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @AfterAll
    private void cleanup(){
        scannerRepository.deleteAll();
    }


    @Test
    @Order(1)
    void addScanner() throws Exception {
        Mockito.when(acunetixApiClient.canProcessRequest(Mockito.any(ScannerType.class))).thenReturn(true);
        Mockito.when(acunetixApiClient.initialize(Mockito.any())).thenReturn(true);
        RoutingDomain routingDomain = createOrGetRoutingDomainService.createOrGetRoutingDomain("default");
        Mockito.when(principal.getName()).thenReturn("admin_scanner");
        ScannerModel scannerModel = ScannerModel.builder()
                .scannerType("Acunetix")
                .accesskey("key")
                .apiUrl("https://scanner_url")
                .proxy(0L)
                .routingDomain(routingDomain.getId())
                .build();
        Mockito.when(acunetixApiClient.saveScanner(Mockito.any())).thenReturn(saveScanner(scannerModel));

        adminScannerRestService.addScanner(scannerModel, "admin_scanner");
        Optional<Scanner> scannerCreated = scannerRepository.findByApiUrlAndScannerType("https://scanner_url", scannerTypeRepository.findByNameIgnoreCase("acunetix"));
        assertTrue(scannerCreated.isPresent());
    }

    private Scanner saveScanner(ScannerModel scannerModel) {
        Scanner scanner = new Scanner();
        scanner.setApiUrl(scannerModel.getApiUrl());
        scanner.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType()));
        return scannerRepository.save(scanner);
    }

    @Test
    @Order(2)
    void showScanners() {
        Mockito.when(principal.getName()).thenReturn("admin_scanner");
        ResponseEntity<List<Scanner>> listResponseEntity = adminScannerRestService.showScanners();
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertNotNull(listResponseEntity.getBody());
        assertTrue(listResponseEntity.getBody().size()>0);
    }

    @Test
    @Order(3)
    void showScannerType() {
        Mockito.when(principal.getName()).thenReturn("admin_scanner");
        ResponseEntity<List<ScannerType>> listResponseEntity = adminScannerRestService.showScannerType();
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertNotNull(listResponseEntity.getBody());
        assertTrue(listResponseEntity.getBody().size()>0);
    }

    @Test
    @Order(5)
    void testScanner() throws Exception {
        Mockito.when(acunetixApiClient.initialize(Mockito.any())).thenReturn(true);
        Optional<Scanner> scannerCreated = scannerRepository.findByApiUrlAndScannerType("https://scanner_url", scannerTypeRepository.findByNameIgnoreCase("acunetix"));
        assertTrue(scannerCreated.isPresent());
        ResponseEntity<Status> statusResponseEntity = adminScannerRestService.testScanner(scannerCreated.get().getId());
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
    }

    @Test
    @Order(7)
    void addRfw() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("admin_scanner");
        Mockito.when(rfwApiClient.getListOfRules(Mockito.any())).thenReturn(new ArrayList<>());
        Optional<Scanner> scannerCreated = scannerRepository.findByApiUrlAndScannerType("https://scanner_url", scannerTypeRepository.findByNameIgnoreCase("acunetix"));
        assertTrue(scannerCreated.isPresent());

        RfwModel rfwModel = new RfwModel();
        rfwModel.setRfwScannerIp("1.1.1.1");
        rfwModel.setRfwUrl("https://rfw");
        adminScannerRestService.addRfw(scannerCreated.get().getId(), rfwModel, "admin_scanner");
        scannerCreated = scannerRepository.findByApiUrlAndScannerType("https://scanner_url", scannerTypeRepository.findByNameIgnoreCase("acunetix"));
        assertTrue(scannerCreated.isPresent());
        assertNotNull(scannerCreated.get().getRfwUrl());
    }

    @Test
    @Order(8)
    void deleteScanner() {
        Mockito.when(principal.getName()).thenReturn("admin_scanner");
        Optional<Scanner> scannerCreated = scannerRepository.findByApiUrlAndScannerType("https://scanner_url", scannerTypeRepository.findByNameIgnoreCase("acunetix"));
        assertTrue(scannerCreated.isPresent());
        ResponseEntity<Status> statusResponseEntity = adminScannerRestService.deleteScanner(scannerCreated.get().getId(), "admin_scanner");
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
    }


}