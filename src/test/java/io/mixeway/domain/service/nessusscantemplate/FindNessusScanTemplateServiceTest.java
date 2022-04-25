package io.mixeway.domain.service.nessusscantemplate;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.NessusScanTemplate;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.NessusScanTemplateRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class FindNessusScanTemplateServiceTest {
    private final FindNessusScanTemplateService findNessusScanTemplateService;
    private final NessusScanTemplateRepository nessusScanTemplateRepository;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;

    @Test
    void findTemplateFor() {
        Scanner scanner = new Scanner();
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NESSUS));
        scanner = scannerRepository.saveAndFlush(scanner);
        NessusScanTemplate nessusScanTemplate = new NessusScanTemplate();
        nessusScanTemplate.setName("Basic Network Scan");
        nessusScanTemplate.setNessus(scanner);
        nessusScanTemplateRepository.save(nessusScanTemplate);
        NessusScanTemplate newScanner = findNessusScanTemplateService.findTemplateFor(scanner);
        assertNotNull(newScanner);
        scannerRepository.delete(scanner);
    }
}