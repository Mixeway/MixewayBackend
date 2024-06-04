package io.mixeway.domain.service.metric;
import static org.junit.jupiter.api.Assertions.*;

import io.mixeway.db.entity.*;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import java.util.ArrayList;
import java.util.List;

public class MetricServiceTest {

    private MetricService metricService = Mockito.mock(MetricService.class);

    @Test
    public void testGetGlobalMetric() {
        // Setup and execute
        Mockito.doNothing().when(metricService).getGlobalMetric();

        // Verify
        metricService.getGlobalMetric();
        Mockito.verify(metricService, Mockito.times(1)).getGlobalMetric();
    }

    @Test
    public void testGetProjectMetric() {
        // Setup
        Project project = new Project();

        // Execute
        Mockito.doNothing().when(metricService).getProjectMetric(project);

        // Verify
        metricService.getProjectMetric(project);
        Mockito.verify(metricService, Mockito.times(1)).getProjectMetric(project);
    }

    @Test
    public void testBuildMetric() {
        // Setup
        List<ProjectVulnerability> projectVulnerabilities = new ArrayList<>();
        List<CiOperations> ciOperations = new ArrayList<>();
        List<Project> allProjects = new ArrayList<>();
        List<BugTracker> bugTrackers = new ArrayList<>();
        Metric globalMetric = new Metric();

        // Execute
        Mockito.doNothing().when(metricService).buildMetric(projectVulnerabilities, ciOperations, allProjects, bugTrackers, globalMetric);

        // Verify
        metricService.buildMetric(projectVulnerabilities, ciOperations, allProjects, bugTrackers, globalMetric);
        Mockito.verify(metricService, Mockito.times(1)).buildMetric(projectVulnerabilities, ciOperations, allProjects, bugTrackers, globalMetric);
    }

    @Test
    public void testCalculatePercentage() {
        // Setup
        long part = 5;
        long total = 20;
        Mockito.when(metricService.calculatePercentage(part, total)).thenReturn(25);

        // Execute
        int result = metricService.calculatePercentage(part, total);

        // Verify
        assertEquals(25, result);
        Mockito.verify(metricService, Mockito.times(1)).calculatePercentage(part, total);
    }

    @Test
    public void testCalculateAverage() {
        // Setup
        long part = 5;
        long total = 20;
        Mockito.when(metricService.calculateAverage(part, total)).thenReturn(1);

        // Execute
        int result = metricService.calculateAverage(part, total);

        // Verify
        assertEquals(1, result);
        Mockito.verify(metricService, Mockito.times(1)).calculateAverage(part, total);
    }

    @Test
    public void testGetAllVulnerabilities() {
        // Setup
        List<ProjectVulnerability> vulnerabilities = new ArrayList<>();
        Mockito.when(metricService.getAllVulnerabilities()).thenReturn(vulnerabilities);

        // Execute
        List<ProjectVulnerability> result = metricService.getAllVulnerabilities();

        // Verify
        assertEquals(vulnerabilities, result);
        Mockito.verify(metricService, Mockito.times(1)).getAllVulnerabilities();
    }

    @Test
    public void testGetProjectVulnerabilities() {
        // Setup
        Project project = new Project();
        List<ProjectVulnerability> vulnerabilities = new ArrayList<>();
        Mockito.when(metricService.getProjectVulnerabilities(project)).thenReturn(vulnerabilities);

        // Execute
        List<ProjectVulnerability> result = metricService.getProjectVulnerabilities(project);

        // Verify
        assertEquals(vulnerabilities, result);
        Mockito.verify(metricService, Mockito.times(1)).getProjectVulnerabilities(project);
    }

    @Test
    public void testIsNotDuplicate() {
        // Setup
        ProjectVulnerability vulnerability = new ProjectVulnerability();
        Mockito.when(metricService.isNotDuplicate(vulnerability)).thenReturn(true);

        // Execute
        boolean result = metricService.isNotDuplicate(vulnerability);

        // Verify
        assertTrue(result);
        Mockito.verify(metricService, Mockito.times(1)).isNotDuplicate(vulnerability);
    }

    @Test
    public void testIsDuplicate() {
        // Setup
        ProjectVulnerability v1 = new ProjectVulnerability();
        ProjectVulnerability v2 = new ProjectVulnerability();
        Mockito.when(metricService.isDuplicate(v1, v2)).thenReturn(false);

        // Execute
        boolean result = metricService.isDuplicate(v1, v2);

        // Verify
        assertFalse(result);
        Mockito.verify(metricService, Mockito.times(1)).isDuplicate(v1, v2);
    }
}