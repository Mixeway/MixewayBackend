package io.mixeway.domain.service.vulnhistory;

import io.mixeway.api.project.model.ProjectVulnTrendChart;
import io.mixeway.api.project.model.ProjectVulnTrendChartSerie;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.AssetHistoryRepository;
import io.mixeway.db.repository.VulnHistoryRepository;
import io.mixeway.domain.service.scanmanager.code.GetOrCreateCodeProjectBranchService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class OperateOnVulnHistoryService {
    private final VulnHistoryRepository vulnHistoryRepository;
    private final GetOrCreateCodeProjectBranchService getOrCreateCodeProjectBranchService;
    private final AssetHistoryRepository assetHistoryRepository;
    private DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");


    public ProjectVulnTrendChart getVulnTrendChart(Project project, int limit){
        LinkedList<Integer> infraVulnTrend = new LinkedList<>();
        LinkedList<Integer> webAppVulnTrend = new LinkedList<>();
        LinkedList<Integer> codeVulnTrend = new LinkedList<>();
        LinkedList<Integer> auditVulnTrend = new LinkedList<>();
        LinkedList<Integer> softwareVulnTrend = new LinkedList<>();
        LinkedList<String> dates = new LinkedList<>();
        List<ProjectVulnTrendChartSerie>series = new ArrayList<>();
        List<VulnHistory> vulnHistories = vulnHistoryRepository.getVulnHistoryLimit(project.getId(),limit) ;
        for(VulnHistory vulnHistory : vulnHistories){
            infraVulnTrend.add(vulnHistory.getInfrastructureVulnHistory().intValue());
            webAppVulnTrend.add(vulnHistory.getWebAppVulnHistory().intValue());
            codeVulnTrend.add(vulnHistory.getCodeVulnHistory().intValue());
            auditVulnTrend.add(vulnHistory.getAuditVulnHistory().intValue());
            softwareVulnTrend.add(vulnHistory.getSoftwarePacketVulnNumber().intValue());
            dates.add(vulnHistory.getInserted().split(" ")[0]);
        }
        if (infraVulnTrend.stream().mapToInt(i-> i).sum() >0){
            ProjectVulnTrendChartSerie infraSerie = new ProjectVulnTrendChartSerie();
            infraSerie.setName(Constants.INFRA_VULN_TREND_LABEL);
            infraSerie.setValues(infraVulnTrend);
            series.add(infraSerie);
        }
        if (webAppVulnTrend.stream().mapToInt(i-> i).sum() >0){
            ProjectVulnTrendChartSerie webAPpSerie = new ProjectVulnTrendChartSerie();
            webAPpSerie.setName(Constants.WEBAPP_VULN_TREND_LABEL);
            webAPpSerie.setValues(webAppVulnTrend);
            series.add(webAPpSerie);
        }
        if (codeVulnTrend.stream().mapToInt(i-> i).sum() >0){
            ProjectVulnTrendChartSerie codeSerie = new ProjectVulnTrendChartSerie();
            codeSerie.setName(Constants.CODE_VULN_TREND_LABEL);
            codeSerie.setValues(codeVulnTrend);
            series.add(codeSerie);
        }
        if (auditVulnTrend.stream().mapToInt(i-> i).sum() >0){
            ProjectVulnTrendChartSerie auditSerie = new ProjectVulnTrendChartSerie();
            auditSerie.setName(Constants.AUDIT_VULN_TREND_LABEL);
            auditSerie.setValues(auditVulnTrend);
            series.add(auditSerie);
        }
        if (softwareVulnTrend.stream().mapToInt(i -> i).sum() > 0){
            ProjectVulnTrendChartSerie softSerie = new ProjectVulnTrendChartSerie();
            softSerie.setName(Constants.SOFT_VULN_TREND_LABEL);
            softSerie.setValues(softwareVulnTrend);
            series.add(softSerie);
        }
        ProjectVulnTrendChart projectVulnTrendChart = new ProjectVulnTrendChart();
        projectVulnTrendChart.setDates(dates);
        projectVulnTrendChart.setSeries(series);
        return projectVulnTrendChart;
    }

    public List<VulnHistory> getLatestVulnHistoryForProject(Project project){
        return vulnHistoryRepository.getVulnHistoryLimit(project.getId(), 30);
    }
    public ProjectVulnTrendChart getVulnTrendChartForCodeProject(CodeProject codeProject, int limit){
        CodeProjectBranch codeProjectBranch = getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject, codeProject.getBranch());
        LinkedList<Integer> sastVulnTrend = new LinkedList<>();
        LinkedList<Integer> scaVulnTrend = new LinkedList<>();
        LinkedList<Integer> iacVulnTrend = new LinkedList<>();
        LinkedList<Integer> secretVulnTrend = new LinkedList<>();
        LinkedList<String> dates = new LinkedList<>();
        List<ProjectVulnTrendChartSerie>series = new ArrayList<>();
        List<AssetHistory> vulnHistories = assetHistoryRepository.getCodeProjectHistory(codeProject.getId(),limit) ;
        for(AssetHistory assetHistory : vulnHistories){
            sastVulnTrend.add(assetHistory.getSastVulns());
            scaVulnTrend.add(assetHistory.getScaVulns());
            secretVulnTrend.add(assetHistory.getSecretVulns());
            iacVulnTrend.add(assetHistory.getIacVulns());
            dates.add(assetHistory.getInserted().format(formatter));
        }
        if (sastVulnTrend.stream().mapToInt(i-> i).sum() >0){
            ProjectVulnTrendChartSerie infraSerie = new ProjectVulnTrendChartSerie();
            infraSerie.setName(Constants.SAST_LABEL);
            infraSerie.setValues(sastVulnTrend);
            series.add(infraSerie);
        }
        if (scaVulnTrend.stream().mapToInt(i-> i).sum() >0){
            ProjectVulnTrendChartSerie webAPpSerie = new ProjectVulnTrendChartSerie();
            webAPpSerie.setName(Constants.SCA_LABEL);
            webAPpSerie.setValues(scaVulnTrend);
            series.add(webAPpSerie);
        }
        if (iacVulnTrend.stream().mapToInt(i-> i).sum() >0){
            ProjectVulnTrendChartSerie codeSerie = new ProjectVulnTrendChartSerie();
            codeSerie.setName(Constants.IAC_LABEL);
            codeSerie.setValues(iacVulnTrend);
            series.add(codeSerie);
        }
        if (secretVulnTrend.stream().mapToInt(i-> i).sum() >0){
            ProjectVulnTrendChartSerie auditSerie = new ProjectVulnTrendChartSerie();
            auditSerie.setName(Constants.SECRET_LABEL);
            auditSerie.setValues(secretVulnTrend);
            series.add(auditSerie);
        }
        ProjectVulnTrendChart projectVulnTrendChart = new ProjectVulnTrendChart();
        projectVulnTrendChart.setDates(dates);
        projectVulnTrendChart.setSeries(series);
        return projectVulnTrendChart;
    }

    public ProjectVulnTrendChart getVulnTrendChartForWebApp(WebApp webApp, int limit){
        LinkedList<Integer> dastVulnTrend = new LinkedList<>();
        LinkedList<String> dates = new LinkedList<>();
        List<ProjectVulnTrendChartSerie>series = new ArrayList<>();
        List<AssetHistory> vulnHistories = assetHistoryRepository.getWebAppHistory(webApp.getId(),limit) ;
        for(AssetHistory assetHistory : vulnHistories){
            dastVulnTrend.add(assetHistory.getDastVulns());
            dates.add(assetHistory.getInserted().format(formatter));
        }
        if (dastVulnTrend.stream().mapToInt(i-> i).sum() >0){
            ProjectVulnTrendChartSerie infraSerie = new ProjectVulnTrendChartSerie();
            infraSerie.setName(Constants.DAST_LABEL);
            infraSerie.setValues(dastVulnTrend);
            series.add(infraSerie);
        }

        ProjectVulnTrendChart projectVulnTrendChart = new ProjectVulnTrendChart();
        projectVulnTrendChart.setDates(dates);
        projectVulnTrendChart.setSeries(series);
        return projectVulnTrendChart;
    }

    public ProjectVulnTrendChart getVulnTrendChartForInterface(Interface anInterface, int limit){
        LinkedList<Integer> intfVulnTrend = new LinkedList<>();
        LinkedList<String> dates = new LinkedList<>();
        List<ProjectVulnTrendChartSerie>series = new ArrayList<>();
        List<AssetHistory> vulnHistories = assetHistoryRepository.getWebAppHistory(anInterface.getId(),limit) ;
        for(AssetHistory assetHistory : vulnHistories){
            intfVulnTrend.add(assetHistory.getNetworkVulns());
            dates.add(assetHistory.getInserted().format(formatter));
        }
        if (intfVulnTrend.stream().mapToInt(i-> i).sum() >0){
            ProjectVulnTrendChartSerie infraSerie = new ProjectVulnTrendChartSerie();
            infraSerie.setName(Constants.DAST_LABEL);
            infraSerie.setValues(intfVulnTrend);
            series.add(infraSerie);
        }

        ProjectVulnTrendChart projectVulnTrendChart = new ProjectVulnTrendChart();
        projectVulnTrendChart.setDates(dates);
        projectVulnTrendChart.setSeries(series);
        return projectVulnTrendChart;
    }


}
