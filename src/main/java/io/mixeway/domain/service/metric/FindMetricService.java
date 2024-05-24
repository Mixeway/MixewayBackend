package io.mixeway.domain.service.metric;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Metric;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.MetricRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class FindMetricService {
    private final MetricRepository metricRepository;

    public Metric getGlobalMetric(){
        return metricRepository.findByProjectIsNull().orElse(new Metric());
    }
    public Metric getProjectMetric(Project project){
        return metricRepository.findByProject(project).orElse(createMetricForProject(project));
    }

    private Metric createMetricForProject(Project project){
        Metric metric = new Metric();
        metric.setProject(project);
        return metric;
    }

}
