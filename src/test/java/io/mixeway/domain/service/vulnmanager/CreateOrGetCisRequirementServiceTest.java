package io.mixeway.domain.service.vulnmanager;

import io.mixeway.db.entity.CisRequirement;
import io.mixeway.db.repository.CisRequirementRepository;
import lombok.AllArgsConstructor;
import org.checkerframework.checker.units.qual.A;
import org.junit.BeforeClass;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@AllArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CreateOrGetCisRequirementServiceTest {

    private final CreateOrGetCisRequirementService createOrGetCisRequirementService;
    private final CisRequirementRepository cisRequirementRepository;


    @Test
    void createOrGetCisRequirement() {
        CisRequirement cisRequirement = createOrGetCisRequirementService.createOrGetCisRequirement("req","type");
        assertEquals(cisRequirement.getId(), cisRequirementRepository.findByNameAndType("req","type").get().getId());
    }
}