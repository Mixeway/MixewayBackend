package io.mixeway.domain.service.softwarepackage;

import io.mixeway.db.entity.SoftwarePacket;
import io.mixeway.db.repository.SoftwarePacketRepository;
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
class GetOrCreateSoftwarePacketServiceTest {
    private final GetOrCreateSoftwarePacketService getOrCreateSoftwarePacketService;
    private final SoftwarePacketRepository softwarePacketRepository;

    @Test
    void getOrCreateSoftwarePacket() {

        SoftwarePacket softwarePacket = getOrCreateSoftwarePacketService.getOrCreateSoftwarePacket("testname","1");
        assertNotNull(softwarePacket);
        Optional<SoftwarePacket> softwarePacketFromRepo = softwarePacketRepository.findByName("testname:1");
        assertTrue(softwarePacketFromRepo.isPresent());

    }

    @Test
    void create() {
        SoftwarePacket softwarePacket = getOrCreateSoftwarePacketService.create("testname2","2");
        assertNotNull(softwarePacket);
        Optional<SoftwarePacket> softwarePacketFromRepo = softwarePacketRepository.findByName("testname2:2");
        assertTrue(softwarePacketFromRepo.isPresent());
    }
}