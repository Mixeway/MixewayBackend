package io.mixeway.domain.service.scannertype;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.ScannerType;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
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
class FindScannerTypeServiceTest {
    private final FindScannerTypeService findScannerTypeService;

    @Test
    void findInfraScannerTypes() {
        List<ScannerType> scannerTypes = findScannerTypeService.findInfraScannerTypes();
        assertTrue(scannerTypes.size() > 0);

    }

    @Test
    void findAll() {
        List<ScannerType> scannerTypes = findScannerTypeService.findAll();
        assertTrue(scannerTypes.size() > 0);
    }

    @Test
    void findByName() {

        ScannerType scannerTypes = findScannerTypeService.findByName(Constants.SCANNER_TYPE_CHECKMARX);
        assertNotNull(scannerTypes);
    }
}