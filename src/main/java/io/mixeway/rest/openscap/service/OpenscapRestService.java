/*
 * @created  2021-01-26 : 10:00
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.rest.openscap.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.RoutingDomainRepository;
import io.mixeway.integrations.audit.plugins.openscap.OpenScapService;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.pojo.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.apache.commons.validator.routines.InetAddressValidator;

import java.security.Principal;
import java.util.Optional;

@Service
public class OpenscapRestService {
    private static final Logger log = LoggerFactory.getLogger(OpenscapRestService.class);
    private final OpenScapService openScapService;
    private final PermissionFactory permissionFactory;
    private final InterfaceRepository interfaceRepository;
    private final AssetRepository assetRepository;
    private final ProjectRepository projectRepository;
    private final RoutingDomainRepository routingDomainRepository;

    public OpenscapRestService(OpenScapService openScapService, PermissionFactory permissionFactory,
                               InterfaceRepository interfaceRepository, AssetRepository assetRepository,
                               ProjectRepository projectRepository, RoutingDomainRepository routingDomainRepository){
        this.openScapService = openScapService;
        this.permissionFactory = permissionFactory;
        this.interfaceRepository = interfaceRepository;
        this.assetRepository = assetRepository;
        this.projectRepository = projectRepository;
        this.routingDomainRepository = routingDomainRepository;
    }

    /**
     * Method which loads multipart file containing Openscap report in XML format to be processed and linked with ipaddress
     *
     * @param file with report
     * @param ipaddress to link result to
     */
    public ResponseEntity<Status> processReport(MultipartFile file, String ipaddress, Long projectId, Principal principal) throws Exception {
        Optional<Project> project = projectRepository.findById(projectId);

        // Check if provided IP Address is correct
        InetAddressValidator validator = InetAddressValidator.getInstance();
        if (!validator.isValid(ipaddress)) {
            log.error("[Openscap] Trying to load OpenScap report for IP {} - invalid IP address",ipaddress );
            return new ResponseEntity<Status>(new Status("Incorrect IP Address"), HttpStatus.BAD_REQUEST);
        }
        // If provided ip address is correct proceed with more checks
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Interface target = null;
            Optional<Interface> anInterface = interfaceRepository.findByAssetInAndPrivateip(project.get().getAssets(), ipaddress);
            if (anInterface.isPresent()){
                target = anInterface.get();
                log.info("[Openscap] Got request to load results of Openscap report for interface {}", LogUtil.prepare(ipaddress));
            } else {
                Asset asest = assetRepository.save(new Asset(ipaddress,routingDomainRepository.findByName(Constants.DEFAULT_ROUTING_DOMAIN), project.get()));
                target = interfaceRepository.save(new Interface(asest, ipaddress));
                log.info("[Openscap] Got request to load results of Openscap report for interface {} - which is created", LogUtil.prepare(ipaddress));
            }
            openScapService.loadOpenScapReport(target,file);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);


    }
}
