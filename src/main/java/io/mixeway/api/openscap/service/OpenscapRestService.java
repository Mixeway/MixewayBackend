/*
 * @created  2021-01-26 : 10:00
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.openscap.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.RoutingDomainRepository;
import io.mixeway.domain.service.asset.GetOrCreateAssetService;
import io.mixeway.domain.service.intf.FindInterfaceService;
import io.mixeway.domain.service.intf.InterfaceOperations;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.routingdomain.FindRoutingDomainService;
import io.mixeway.scanmanager.service.audit.OpenScapService;
import io.mixeway.utils.LogUtil;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.conn.util.InetAddressUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.security.Principal;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Log4j2
public class OpenscapRestService {
    private final OpenScapService openScapService;
    private final PermissionFactory permissionFactory;
    private final FindProjectService findProjectService;
    private final FindInterfaceService findInterfaceService;
    private final GetOrCreateAssetService getOrCreateAssetService;
    private final InterfaceOperations interfaceOperations;
    private final FindRoutingDomainService findRoutingDomainService;


    /**
     * Method which loads multipart file containing Openscap report in XML format to be processed and linked with ipaddress
     *
     * @param file with report
     * @param ipaddress to link result to
     */
    public ResponseEntity<Status> processReport(MultipartFile file, String ipaddress, Long projectId, Principal principal) throws Exception {
        Optional<Project> project = findProjectService.findProjectById(projectId);
        if (ipaddress.endsWith(".")){
            ipaddress = StringUtils.chop(ipaddress);
        }
        // Check if provided IP Address is correct
        //InetAddressValidator validator = InetAddressValidator.getInstance();
        if (!InetAddressUtils.isIPv4Address(ipaddress)) {
            log.error("[Openscap] Trying to load OpenScap report for IP {} - invalid IP address",ipaddress );
            return new ResponseEntity<Status>(new Status("Incorrect IP Address"), HttpStatus.BAD_REQUEST);
        }
        // If provided ip address is correct proceed with more checks
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Interface target = null;
            Optional<Interface> anInterface = findInterfaceService.getInterfacesForProjectAndWithIP(project.get(), ipaddress);

            if (anInterface.isPresent()){
                target = anInterface.get();
                log.info("[Openscap] Got request to load results of Openscap report for interface {}", LogUtil.prepare(ipaddress));
            } else {
                Asset asest = getOrCreateAssetService
                        .getOrCreateAsset(ipaddress,findRoutingDomainService.findByName(Constants.DEFAULT_ROUTING_DOMAIN), project.get());
                log.info("[Openscap] Got request to load results of Openscap report for interface {} - which is created", LogUtil.prepare(ipaddress));
            }
            openScapService.loadOpenScapReport(target,file);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);


    }
}
