package io.mixeway.plugins.codescan.controller;

import io.mixeway.plugins.codescan.service.CodeScanClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import io.mixeway.db.entity.CodeVuln;
import io.mixeway.plugins.codescan.service.CodeScanService;
import io.mixeway.plugins.audit.mvndependencycheck.model.SASTRequestVerify;
import io.mixeway.plugins.utils.CodeAccessVerifier;
import io.mixeway.pojo.Status;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

@RestController
public class CodeScanController {
    private final CodeScanService codeScanService;
    private final CodeAccessVerifier codeAccessVerifier;
    private final List<CodeScanClient> codeScanClients;

    @Autowired
    CodeScanController(CodeScanService codeScanService, List<CodeScanClient> codeScanClients, CodeAccessVerifier codeAccessVerifier){
        this.codeScanService = codeScanService;
        this.codeAccessVerifier = codeAccessVerifier;
        this.codeScanClients = codeScanClients;
    }


    @PreAuthorize("hasAuthority('ROLE_API')")
    @RequestMapping(value = "/api/sast/{projectId}/create/{groupName}/{projectName}", method = RequestMethod.PUT,produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Status> createScanForProject(@PathVariable(value = "projectId") Long id,
                                                       @PathVariable(value="groupName") String groupName,
                                                       @PathVariable(value="projectName") String projectName) throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException {
        SASTRequestVerify sastRequestVerify = codeAccessVerifier.verifyPermissions(id,groupName,projectName);
        if (sastRequestVerify.getValid()){
            for(CodeScanClient codeScanClient : codeScanClients){
                if (codeScanClient.canProcessRequest(sastRequestVerify.getCg())){
                    if (codeScanClient.runScan(sastRequestVerify.getCg(),sastRequestVerify.getCp())){
                        return new ResponseEntity<>(new Status("OK"), HttpStatus.CREATED);
                    } else {
                        return new ResponseEntity<>(new Status("Queued"), HttpStatus.CREATED);
                    }
                }
            }
        } else {
            return new ResponseEntity<>(new Status("Scan for given resource is not yet configured."), HttpStatus.PRECONDITION_FAILED);
        }
        return new ResponseEntity<>(new Status("Something went wrong"), HttpStatus.PRECONDITION_FAILED);
    }

//    @PreAuthorize("hasAuthority('ROLE_API')")
//    @PutMapping("/api/sast/create/{projectId}/{groupName}")
//    public ResponseEntity<Status> createScanForGroup(@PathVariable(value = "projectId") Long id,
//                                                       @PathVariable(value="groupName") String groupName) {
//        return null;
//    }

    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping("/api/sast/show/{projectId}/{groupName}/{projectNane}")
    public ResponseEntity<List<CodeVuln>> getResultsForProjectScan(@PathVariable(value = "projectId") Long id,
                                                                   @PathVariable(value="groupName") String groupName,
                                                                   @PathVariable(value="projectNane") String projectName)  {

        return codeScanService.getResultsForProject(id,groupName,projectName);
    }

//    @PreAuthorize("hasAuthority('ROLE_API')")
//    @GetMapping("/api/sast/show/{projectId}/{groupName}")
//    public ResponseEntity<Status> getResultsForGroupScan(@PathVariable(value = "projectId") Long id,
//                                                     @PathVariable(value="groupName") String groupName) throws UnknownHostException {
//        return null;
//    }

}
