package io.mixeway.domain.service.nessusscantemplate;

import io.mixeway.db.entity.NessusScanTemplate;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.NessusScanTemplateRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;


/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindNessusScanTemplateService {
    private String NESSUS_TEMPLATE = "Basic Network Scan";
    private final NessusScanTemplateRepository nessusScanTemplateRepository;

    public NessusScanTemplate findTemplateFor(Scanner scanner){
        return nessusScanTemplateRepository.findByNameAndNessus(NESSUS_TEMPLATE, scanner);
    }
}
