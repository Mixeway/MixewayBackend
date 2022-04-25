package io.mixeway.domain.service.scanner;

import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.ScannerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class UpdateScannerService {
    private final ScannerRepository scannerRepository;

    public void decreaseScanNumber(Scanner scanner) {
        scanner.setRunningScans(scanner.getRunningScans() - 1);
        scannerRepository.save(scanner);
    }
    public void increaseScanNumber(Scanner scanner) {
        scanner.setRunningScans(scanner.getRunningScans() + 1);
        scannerRepository.save(scanner);
    }
}
