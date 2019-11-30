package io.mixeway.plugins.audit.mvndependencycheck.controller;

import io.mixeway.plugins.utils.CodeAccessVerifier;
import io.mixeway.pojo.Status;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import io.mixeway.plugins.audit.mvndependencycheck.service.MvnDependencyCheckUploadService;
import io.mixeway.plugins.audit.mvndependencycheck.model.SASTRequestVerify;

import java.io.IOException;

@Controller
public class MvnDependencyCheckUploadController {
    private final MvnDependencyCheckUploadService mvnDependencyCheckUploadService;
    private final CodeAccessVerifier codeAccessVerifier;
    @Autowired
    MvnDependencyCheckUploadController(MvnDependencyCheckUploadService mvnDependencyCheckUploadService,
                                       CodeAccessVerifier codeAccessVerifier){
        this.mvnDependencyCheckUploadService = mvnDependencyCheckUploadService;
        this.codeAccessVerifier = codeAccessVerifier;
    }
    @CrossOrigin(origins="*")
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/api/mvndependencycheck/{projectId}/{codeGroup}/{codeProject}",produces = "application/json")
    public ResponseEntity<Status> mvnDependencyCheck(@PathVariable(value = "codeGroup") String codeGroup,
                                                     @PathVariable(value = "codeProject") String codeProject,
                                                     @PathVariable(value = "projectId") Long id,
                                                     @RequestParam("file") MultipartFile file) throws IOException {
        SASTRequestVerify sastRequestVerify = codeAccessVerifier.verifyPermissions(id,codeGroup,codeProject);
        if (sastRequestVerify.getValid()) {
            return mvnDependencyCheckUploadService.mvnDependencyCheck(codeGroup, codeProject, id, file);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
}
