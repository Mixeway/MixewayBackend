package io.mixeway.domain.service.scanner;

import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.ScannerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindScannerService {
    private final ScannerRepository scannerRepository;

    public List<Scanner> findAllScanners(){
        return scannerRepository.findAll();
    }

    public Optional<Scanner> findById(long id){
        return scannerRepository.findById(id);
    }
}
