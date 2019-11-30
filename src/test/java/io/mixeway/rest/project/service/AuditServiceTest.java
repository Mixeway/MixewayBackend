package io.mixeway.rest.project.service;

import io.mixeway.db.entity.Project;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import io.mixeway.config.TestConfig;
import io.mixeway.db.entity.Node;
import io.mixeway.db.entity.NodeAudit;
import io.mixeway.db.entity.Requirement;
import io.mixeway.db.repository.NodeAuditRepository;
import io.mixeway.db.repository.NodeRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.RequirementRepository;

import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;
import javax.transaction.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)

public class AuditServiceTest {
    AuditService auditService;
    @Autowired
    ProjectRepository projectRepository;
    @Autowired
    NodeRepository nodeRepository;
    @Autowired
    NodeAuditRepository nodeAuditRepository;
    @Autowired
    RequirementRepository requirementRepository;
    @Before
    public void setUp(){
        auditService = new AuditService(projectRepository);
        initializeDb();
    }

    private void initializeDb() {
        Project project = new Project();
        project.setName("test");
        projectRepository.save(project);
        Node node = new Node();
        node.setProject(project);
        node.setType("test");
        node.setName("testNode");
        nodeRepository.save(node);
        Requirement requirement = new Requirement();
        requirement.setCode("1");
        requirement.setName("testReq");
        requirement.setSeverity(6);
        requirementRepository.save(requirement);
        NodeAudit nodeAudit = new NodeAudit();
        nodeAudit.setScore("FAIL");
        nodeAudit.setUpdated("1990-10-10");
        nodeAudit.setRequirement(requirement);
        nodeAuditRepository.save(nodeAudit);
        project.setNodes(new HashSet<Node>(nodeRepository.findAll()));
        projectRepository.save(project);
        node.setNodeAudits(new HashSet<>(nodeAuditRepository.findAll()));
        nodeRepository.save(node);
    }

    @Test
    @Transactional
    public void showAudit() {
        Optional<Project> project = Optional.of(projectRepository.findByName("test").get().get(0));
        Assertions.assertThat(project.isPresent()).isTrue();
        ResponseEntity<List<NodeAudit>> audit = auditService.showAudit(project.get().getId());
        Assertions.assertThat(audit.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(audit.getBody().size()).isEqualTo(1);


    }
}
