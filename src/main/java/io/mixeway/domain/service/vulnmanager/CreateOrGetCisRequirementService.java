package io.mixeway.domain.service.vulnmanager;

import io.mixeway.db.entity.CisRequirement;
import io.mixeway.db.repository.CisRequirementRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
public class CreateOrGetCisRequirementService {
    private final CisRequirementRepository cisRequirementRepository;

    public CreateOrGetCisRequirementService(CisRequirementRepository cisRequirementRepository){
        this.cisRequirementRepository = cisRequirementRepository;
    }
    public CisRequirement createOrGetCisRequirement(String name, String type){
        Optional<CisRequirement> cisRequirement = cisRequirementRepository.findByNameAndType(name,type);
        if (cisRequirement.isPresent()){
            return cisRequirement.get();
        } else {
            CisRequirement cisRequirementNew = new CisRequirement(name,type);
            return cisRequirementRepository.save(cisRequirementNew);
        }
    }

}
