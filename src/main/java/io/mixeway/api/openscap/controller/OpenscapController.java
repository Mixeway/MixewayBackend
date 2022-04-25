/*
 * @created  2021-01-26 : 09:59
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.openscap.controller;

import io.mixeway.api.openscap.service.OpenscapRestService;
import io.mixeway.utils.Status;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.security.Principal;

@Controller
    @RequestMapping("/v2/api/openscap")
public class OpenscapController {

    private final OpenscapRestService openscapRestService;

    public OpenscapController(OpenscapRestService openscapRestService){
        this.openscapRestService = openscapRestService;
    }

    /**
     * Method which loads multipart file containing Openscap report in XML format to be processed and linked with ipaddress
     *
     * @param file with report
     * @param ipaddress to link result to
     */
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/project/{projectid}/interface/{ipaddress}")
    public ResponseEntity<Status> getOpenScapReport(@RequestParam("file") MultipartFile file, @PathVariable(value = "ipaddress") String ipaddress,
                                                    @PathVariable(value = "projectid") Long projectId, Principal principal) throws Exception {
        return openscapRestService.processReport(file,ipaddress, projectId, principal);
    }
}
