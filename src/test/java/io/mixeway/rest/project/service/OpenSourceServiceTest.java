package io.mixeway.rest.project.service;

import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeProjectRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import io.mixeway.config.TestConfig;
import io.mixeway.db.entity.SoftwarePacket;
import io.mixeway.db.entity.SoftwarePacketVulnerability;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SoftwarePacketRepository;
import io.mixeway.db.repository.SoftwarePacketVulnerabilityRepository;

import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)
public class OpenSourceServiceTest {
    OpenSourceService openSourceServie;
    @Autowired
    ProjectRepository projectRepository;
    @Autowired
    CodeProjectRepository codeProjectRepository;
    @Autowired
    SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;
    @Autowired
    SoftwarePacketRepository softwarePacketRepository;
    @Before
    public void setUp(){
        openSourceServie = new OpenSourceService(projectRepository, codeProjectRepository, softwarePacketVulnerabilityRepository);
        initializeDB();
    }

    private void initializeDB() {
        Project p = new Project();
        p.setName("test");
        p = projectRepository.save(p);
        SoftwarePacket sp = new SoftwarePacket();
        sp.setName("tes");
        sp.setUptated(true);
        sp = softwarePacketRepository.save(sp);
        SoftwarePacketVulnerability softwarePacketVulnerability = new SoftwarePacketVulnerability();
        softwarePacketVulnerability.setName("test");
        softwarePacketVulnerability.setDescription("testt");
        softwarePacketVulnerability.setProject(p);
        softwarePacketVulnerability.setSoftwarepacket(sp);
        softwarePacketVulnerability.setScore(7.9);
        softwarePacketVulnerability.setSeverity("Critic");
        softwarePacketVulnerabilityRepository.save(softwarePacketVulnerability);
    }

    @Test
    public void showSoft() {
        //ResponseEntity<List<SoftVuln>> result = openSourceServie.showSoft(projectRepository.findByName("test").get().stream().findFirst().get().getId());
        //Assertions.assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        //Assertions.assertThat(result.getBody().size()).isGreaterThan(0);

    }
}
