package io.mixeway.plugins.audit.cisbenchmark.Controller;

import io.mixeway.plugins.audit.cisbenchmark.Service.CisDockerBenchmarkService;
import io.mixeway.plugins.audit.cisbenchmark.Service.CisK8sBenchmarkService;
import io.mixeway.pojo.Status;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Controller
public class CisBenchmarkApiController
{
    private final CisK8sBenchmarkService cisK8sBenchmarkService;
    private final CisDockerBenchmarkService cisDockerBenchmarkService;

    @Autowired
    CisBenchmarkApiController(CisK8sBenchmarkService cisK8sBenchmarkService, CisDockerBenchmarkService cisDockerBenchmarkService){
        this.cisK8sBenchmarkService = cisK8sBenchmarkService;
        this.cisDockerBenchmarkService = cisDockerBenchmarkService;
    }

    //@PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/api/cis-k8s/{projectId}")
    public ResponseEntity<Status> getCisReport(@RequestParam("file") MultipartFile file, @PathVariable(value = "projectId") Long id) throws IOException {
        return cisK8sBenchmarkService.processK8sReport(file,id);
    }
    @PostMapping(value = "/api/cis-docker/{projectId}")
    public ResponseEntity<Status> getCisDocker(@RequestParam("file") MultipartFile file, @PathVariable(value = "projectId") Long id) {
        return cisDockerBenchmarkService.getCisDocker(file,id);
    }
}
