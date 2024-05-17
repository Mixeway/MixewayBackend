package io.mixeway.domain.service.scan;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.ScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class FindScanService {
    private final ScanRepository scanRepository;


    public List<Scan> getScansForAsset(Scannable scannable){
        if (scannable instanceof CodeProject){
            return scanRepository.findByCodeProject((CodeProject)scannable);
        } else if (scannable instanceof WebApp){
            return scanRepository.findByWebapp((WebApp) scannable);
        } else if (scannable instanceof Interface){
            return scanRepository.findByInterfaceObj((Interface) scannable);
        }
        return new ArrayList<>();
    }
}
