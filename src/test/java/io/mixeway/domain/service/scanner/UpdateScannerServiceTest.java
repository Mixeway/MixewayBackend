package io.mixeway.domain.service.scanner;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UpdateScannerServiceTest {
    private final ScannerRepository scannerRepository;
    private final UpdateScannerService updateScannerService;
    private final ScannerTypeRepository scannerTypeRepository;

    @AfterAll
    public void cleanup(){
        scannerRepository.deleteAll();
    }

    @Test
    void decreaseScanNumber() {
        Scanner scanner = new Scanner();
        scanner.setApiUrl("update");
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_CHECKMARX));
        scanner.setStatus(true);
        scanner = scannerRepository.saveAndFlush(scanner);
        int scanNumber = scanner.getRunningScans();
        updateScannerService.decreaseScanNumber(scanner);
        Optional<Scanner> scannernew = scannerRepository.findByApiUrlAndScannerType("update",scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_CHECKMARX));
        assertTrue(scannernew.isPresent());
        assertEquals(scanNumber-1, scannernew.get().getRunningScans());
    }

    @Test
    void increaseScanNumber() {
        Scanner scanner = new Scanner();
        scanner.setApiUrl("updat2");
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NEXPOSE));
        scanner.setStatus(true);
        scanner = scannerRepository.saveAndFlush(scanner);
        int scanNumber = scanner.getRunningScans();
        updateScannerService.increaseScanNumber(scanner);
        Optional<Scanner> scannernew = scannerRepository.findByApiUrlAndScannerType("updat2",scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NEXPOSE));
        assertTrue(scannernew.isPresent());
        assertEquals(scanNumber+1, scannernew.get().getRunningScans());
    }
}