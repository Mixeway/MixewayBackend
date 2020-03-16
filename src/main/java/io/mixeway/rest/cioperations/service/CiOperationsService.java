package io.mixeway.rest.cioperations.service;

import io.mixeway.db.entity.Project;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.rest.cioperations.model.CiResultModel;
import io.mixeway.rest.model.OverAllVulnTrendChartData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.db.entity.CiOperations;
import io.mixeway.db.repository.CiOperationsRepository;

import java.security.Principal;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CiOperationsService {
    private final CiOperationsRepository ciOperationsRepository;
    private final PermissionFactory permissionFactory;

    @Autowired
    CiOperationsService(CiOperationsRepository ciOperationsRepository, PermissionFactory permissionFactory){
        this.ciOperationsRepository = ciOperationsRepository;
        this.permissionFactory = permissionFactory;
    }

    public ResponseEntity<List<OverAllVulnTrendChartData>> getVulnTrendData(Principal principal) {
        List<Project> projects = permissionFactory.getProjectForPrincipal(principal);
        return new ResponseEntity<>(ciOperationsRepository.getCiTrend(projects.stream().map(Project::getId).collect(Collectors.toList())), HttpStatus.OK);
    }

    public ResponseEntity<CiResultModel> getResultData(Principal principal) {
        CiResultModel ciResultModel = new CiResultModel();
        List<Project> projects = permissionFactory.getProjectForPrincipal(principal);
        ciResultModel.setNotOk(ciOperationsRepository.countByResultAndProjectIn("Not Ok", projects));
        ciResultModel.setOk(ciOperationsRepository.countByResultAndProjectIn("Ok", projects));
        return new ResponseEntity<>( ciResultModel, HttpStatus.OK);
    }

    public ResponseEntity<List<CiOperations>> getTableData(Principal principal) {
        return new ResponseEntity<>(ciOperationsRepository.findByProjectInOrderByInsertedDesc(permissionFactory.getProjectForPrincipal(principal)), HttpStatus.OK);
    }
}
