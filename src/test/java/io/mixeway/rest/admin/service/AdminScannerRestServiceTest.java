package io.mixeway.rest.admin.service;

import org.assertj.core.api.Assertions;
import org.codehaus.jettison.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.vault.core.VaultOperations;
import io.mixeway.config.TestConfig;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.db.repository.ProxiesRepository;
import io.mixeway.db.repository.RoutingDomainRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.plugins.codescan.fortify.apiclient.FortifyApiClient;
import io.mixeway.plugins.infrastructurescan.nessus.apiclient.NessusApiClient;
import io.mixeway.plugins.infrastructurescan.service.NetworkScanClient;
import io.mixeway.plugins.remotefirewall.apiclient.RfwApiClient;
import io.mixeway.pojo.SecurityScanner;
import io.mixeway.pojo.Status;
import io.mixeway.rest.model.RfwModel;
import io.mixeway.rest.model.ScannerModel;

import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;
import javax.transaction.Transactional;
import javax.xml.bind.JAXBException;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)
@Transactional
public class AdminScannerRestServiceTest {
    @Autowired
    private ScannerRepository scannerRepository;
    @Autowired
    private ScannerTypeRepository scannerTypeRepository;
    @Autowired
    private ProxiesRepository proxiesRepository;
    @Mock
    private VaultOperations operations;
    @Mock
    private FortifyApiClient fortifyApiClient;
    @Mock
    private NessusApiClient nessusApiClient;
    @Mock
    private RfwApiClient rfwApiClient;
    List<NetworkScanClient> networkScanClients = new ArrayList<>();
    List<SecurityScanner> securityScanners = new ArrayList<>();
    @Autowired
    private RoutingDomainRepository routingDomainRepository;
    private AdminScannerRestService adminScannerRestService;
    @Before
    public void setUp(){
        MockitoAnnotations.initMocks(this);
        securityScanners.add(fortifyApiClient);
        securityScanners.add(nessusApiClient);
        networkScanClients.add(nessusApiClient);
        adminScannerRestService = new AdminScannerRestService(routingDomainRepository,securityScanners,rfwApiClient,
                operations,proxiesRepository,scannerTypeRepository, scannerRepository);
        
        Scanner scanner = new Scanner();
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase("nessus"));
        scanner.setApiUrl("http://test");
        scannerRepository.save(scanner);
    }

    @Test
    public void showScanners() {
        ResponseEntity<List<Scanner>> response = adminScannerRestService.showScanners();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void showScannerType() {
        ResponseEntity<List<ScannerType>> response = adminScannerRestService.showScannerType();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(Objects.requireNonNull(response.getBody()).size()).isGreaterThan(0);
    }

    @Test
    public void addScanner() {
        Mockito.when(operations.write(any(String.class), any(String.class))).thenReturn(null);
        ScannerModel scannerModel = new ScannerModel();
        scannerModel.setAccesskey("test");
        scannerModel.setSecretkey("test");
        scannerModel.setProxy(0L);
        scannerModel.setScannerType("nessus");
        scannerModel.setApiUrl("http://test.pl");
        scannerModel.setRoutingDomain(1L);
        ResponseEntity<Status> response = adminScannerRestService.addScanner(scannerModel,"test");
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    public void deleteScanner() {
        Mockito.when(operations.write(any(String.class), any(String.class))).thenReturn(null);
        ScannerModel scannerModel = new ScannerModel();
        scannerModel.setAccesskey("test");
        scannerModel.setSecretkey("test");
        scannerModel.setProxy(0L);
        scannerModel.setScannerType("nessus");
        scannerModel.setApiUrl("http://test.pl");
        scannerModel.setRoutingDomain(1L);
        ResponseEntity<Status> response = adminScannerRestService.addScanner(scannerModel,"test");
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        Optional<Scanner> scanner = scannerRepository.findByApiUrlAndScannerType("http://test", scannerTypeRepository.findByNameIgnoreCase("nessus"));
        response = adminScannerRestService.deleteScanner(scanner.get().getId(),"test");
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        scanner = scannerRepository.findByApiUrlAndScannerType(scannerModel.getApiUrl(), scannerTypeRepository.findByNameIgnoreCase("nessus"));
        Assertions.assertThat(scanner.isPresent()).isEqualTo(false);
    }

    @Test
    public void testScanner() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, IOException, JAXBException {
        Mockito.when(operations.write(any(String.class), any(String.class))).thenReturn(null);
        Mockito.when(nessusApiClient.initialize(any(Scanner.class))).thenReturn(true);
        ScannerModel scannerModel = new ScannerModel();
        scannerModel.setAccesskey("test");
        scannerModel.setSecretkey("test");
        scannerModel.setProxy(0L);
        scannerModel.setScannerType("nessus");
        scannerModel.setApiUrl("http://test.pl");
        scannerModel.setRoutingDomain(1L);
        ResponseEntity<Status> response = adminScannerRestService.addScanner(scannerModel,"test");
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        Optional<Scanner> scanner = scannerRepository.findByApiUrlAndScannerType("http://test", scannerTypeRepository.findByNameIgnoreCase("nessus"));
        response = adminScannerRestService.testScanner(scanner.get().getId());
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void addRfw() throws Exception {
        Mockito.when(operations.write(any(String.class), any(String.class))).thenReturn(null);
        for (SecurityScanner securityScanner: securityScanners){
            Mockito.doNothing().when(securityScanner).saveScanner(any(ScannerModel.class));
        }
        Optional<Scanner> scanner = scannerRepository.findByApiUrlAndScannerType("http://test", scannerTypeRepository.findByNameIgnoreCase("nessus"));
        RfwModel rfwModel = new RfwModel();
        rfwModel.setRfwPassword("test");
        rfwModel.setRfwScannerIp("1.1.1.1");
        rfwModel.setRfwUrl("2.2.2.2");
        rfwModel.setRfwUsername("test");
        ResponseEntity<Status> response = adminScannerRestService.addRfw(scanner.get().getId(), rfwModel, "tes");
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }
}