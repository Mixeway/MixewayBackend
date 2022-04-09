package io.mixeway.domain.service.scanner;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class DeleteScannerServiceTest {
    private final DeleteScannerService deleteScannerService;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;

    @Test
    void removeScanner() {
        Scanner scanner = new Scanner();
        scanner.setApiUrl("https://todelete");
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NEXPOSE));
        scannerRepository.save(scanner);
        deleteScannerService.removeScanner(scanner.getId());
        Optional<Scanner> find = scannerRepository.findById(scanner.getId());
        assertFalse(find.isPresent());
    }
}