package io.mixeway.domain.service.intf;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.db.repository.InterfaceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindInterfaceService {
    private final InterfaceRepository interfaceRepository;

    /**
     * Returning List of Intrafces within specified project in specified RoutingDomain
     * @param routingDomain
     * @param project
     * @return
     */
    public Set<Interface> getInterfacesForProjectAndRoutingDomains(RoutingDomain routingDomain, Project project) {
        return interfaceRepository.findByAssetInAndRoutingDomainAndActive(project.getAssets(), routingDomain, true);
    }

    public List<Interface> getInterfacesInProject(Project project){
        return interfaceRepository.findByAssetInAndActive(new ArrayList<>(project.getAssets()), true);
    }

    public Optional<Interface> getInterfacesForProjectAndWithIP(Project project, String ipaddress) {
        return  interfaceRepository.findByAssetInAndPrivateip(project.getAssets(), ipaddress);
    }

    public List<Interface> findByAssetIn(ArrayList<Asset> assets) {
        return interfaceRepository.findByAssetIn(assets);
    }

    public Optional<Interface> findById(Long assetId) {
        return interfaceRepository.findById(assetId);
    }

    public List<Interface> findByActive(boolean b) {
        return interfaceRepository.findByActive(b);
    }
}
