package io.mixeway.rest.cioperations.service;

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
import io.mixeway.db.repository.CiOperationsRepository;

import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;
import javax.transaction.Transactional;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)
@Transactional
public class CiOperationsServiceTest {
    @Autowired
    CiOperationsRepository ciOperationsRepository;
    private CiOperationsService ciOperationsService;

    @Before
    public void setUp(){
        this.ciOperationsService = new CiOperationsService(ciOperationsRepository,null,null,null,null
        ,null,null,null);
    }

    @Test
    public void getVulnTrendData() {

    }

    @Test
    public void getResultData() {
    }

    @Test
    public void getTableData() {
    }
}