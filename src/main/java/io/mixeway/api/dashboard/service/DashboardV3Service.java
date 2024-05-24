package io.mixeway.api.dashboard.service;

import io.mixeway.db.entity.Metric;
import io.mixeway.db.entity.Project;
import io.mixeway.domain.service.metric.FindMetricService;
import io.mixeway.domain.service.metric.MetricService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.utils.PermissionFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class DashboardV3Service {
    private final PermissionFactory permissionFactory;
    private final MetricService metricService;
    private final FindProjectService findProjectService;
    private final FindMetricService findMetricService;

    public Metric getMetricForProject(long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            return findMetricService.getProjectMetric(project.get());
        }
        else return new Metric();
    }
}
