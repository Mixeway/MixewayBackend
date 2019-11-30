package io.mixeway.rest.cioperations.service;

import io.mixeway.rest.cioperations.model.CiResultModel;
import io.mixeway.rest.model.OverAllVulnTrendChartData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.db.entity.CiOperations;
import io.mixeway.db.repository.CiOperationsRepository;

import java.util.List;

@Service
public class CiOperationsService {
    private final CiOperationsRepository ciOperationsRepository;

    @Autowired
    CiOperationsService(CiOperationsRepository ciOperationsRepository){
        this.ciOperationsRepository = ciOperationsRepository;
    }

    public ResponseEntity<List<OverAllVulnTrendChartData>> getVulnTrendData() {
        return new ResponseEntity<>(ciOperationsRepository.getCiTrend(), HttpStatus.OK);
    }

    public ResponseEntity<CiResultModel> getResultData() {
        CiResultModel ciResultModel = new CiResultModel();
        ciResultModel.setNotOk(ciOperationsRepository.countByResult("Not Ok"));
        ciResultModel.setOk(ciOperationsRepository.countByResult("Ok"));
        return new ResponseEntity<>( ciResultModel, HttpStatus.OK);
    }

    public ResponseEntity<List<CiOperations>> getTableData() {
        return new ResponseEntity<>(ciOperationsRepository.findAllByOrderByInsertedDesc(), HttpStatus.OK);
    }
}
