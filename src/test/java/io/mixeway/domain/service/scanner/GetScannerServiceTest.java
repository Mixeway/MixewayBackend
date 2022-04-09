package io.mixeway.domain.service.scanner;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GetScannerServiceTest {
    private final GetScannerService getScannerService;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final VulnTemplate vulnTemplate;

    @AfterAll
    public void cleanup(){
        scannerRepository.deleteAll();
    }

    @Test
    void getCodeScanners() {
        Scanner scanner = new Scanner();
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_CHECKMARX));
        scanner.setStatus(true);
        scannerRepository.save(scanner);
        Optional<Scanner> scannerList = getScannerService.getCodeScanners();
        assertTrue(scannerList.isPresent());

    }

    @Test
    void getScannerForWebApp() {
        Scanner scanner = new Scanner();
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_ACUNETIX));
        scanner.setStatus(true);
        scannerRepository.save(scanner);
        Optional<Scanner> scannerList = getScannerService.getCodeScanners();
        assertTrue(scannerList.isPresent());
    }

    @Test
    void getScannerForInfraScan() {

        Scanner scanner = new Scanner();
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS));
        scanner.setStatus(true);
        scannerRepository.save(scanner);
        Optional<Scanner> scannerList = getScannerService.getCodeScanners();
        assertTrue(scannerList.isPresent());
    }

    @Test
    void getOpenSourceScanner() {

        Scanner scanner = new Scanner();
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK));
        scanner.setStatus(true);
        scannerRepository.save(scanner);
        Optional<Scanner> scannerList = getScannerService.getCodeScanners();
        assertTrue(scannerList.isPresent());
    }
}