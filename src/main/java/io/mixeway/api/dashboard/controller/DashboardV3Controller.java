package io.mixeway.api.dashboard.controller;

import io.mixeway.api.dashboard.service.DashboardV3Service;
import io.mixeway.db.entity.Metric;
import io.mixeway.domain.service.metric.FindMetricService;
import io.mixeway.domain.service.metric.MetricService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@RestController
@RequestMapping("/v3/api/dashboard")
@RequiredArgsConstructor
public class DashboardV3Controller {
    private final FindMetricService findMetricService;
    private final DashboardV3Service dashboardV3Service;

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/metric")
    public ResponseEntity<Metric> countMetrics() {
        return new ResponseEntity<>(findMetricService.getGlobalMetric(), HttpStatus.OK);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/project/{id}/metric")
    public ResponseEntity<Metric> countMetricsForProject(@PathVariable("id") Long id, Principal principal) {

        return new ResponseEntity<>(dashboardV3Service.getMetricForProject(id, principal), HttpStatus.OK);
    }

}
