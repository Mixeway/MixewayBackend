package io.mixeway.pojo;

import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.InterfaceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import io.mixeway.db.entity.InfrastructureVuln;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.InfrastructureVulnRepository;
import io.mixeway.db.repository.WebAppRepository;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Component
public class WebAppHelper {
    private static final Logger log = LoggerFactory.getLogger(WebAppHelper.class);
    private InfrastructureVulnRepository infrastructureVulnRepository;
    private InterfaceRepository interfaceRepository;
    private WebAppRepository webAppRepository;

    @Autowired
    WebAppHelper(InfrastructureVulnRepository infrastructureVulnRepository, InterfaceRepository interfaceRepository,
                 WebAppRepository webAppRepository){
        this.infrastructureVulnRepository = infrastructureVulnRepository;
        this.interfaceRepository = interfaceRepository;
        this.webAppRepository = webAppRepository;
    }

    public void discoverWebAppFromInfrastructureVulns(Project project){
        List<Interface> interfaces = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        List<InfrastructureVuln> vulns = infrastructureVulnRepository.getVulnsByInterfacesAndWithWWW(interfaces);
        List<InfrastructureVuln> uniqueWWW = vulns
                .stream()
                .filter(distinctByKeys(InfrastructureVuln::getIntf, InfrastructureVuln::getPort))
                .collect(Collectors.toList());
        createOrVerifyWebApps(project, uniqueWWW);

    }
    @Transactional(rollbackFor = Exception.class)
    void createOrVerifyWebApps(Project project, List<InfrastructureVuln> vulns){
        for (InfrastructureVuln iv : vulns){
            String port = iv.getPort().split("/")[0].trim();
            String proto ="http://";
            if (port.endsWith("443")){
                proto="https://";
            }
            String url = proto+iv.getIntf().getPrivateip()+":"+port;
            Optional<WebApp> webApp = webAppRepository.findByUrl(url);
            try {
                if (!webApp.isPresent()) {
                    WebApp webAppToCreate = new WebApp();
                    webAppToCreate.setProject(project);
                    webAppToCreate.setUrl(url);
                    webAppToCreate.setRunning(false);
                    webAppToCreate.setAutoStart(true);
                    webAppToCreate.setPublicscan(iv.getIntf().getRoutingDomain().getName().equals("Internet"));
                    webAppRepository.save(webAppToCreate);
                    log.info("Created WebApp for project {} - {}", project.getName(), webAppToCreate.getUrl());
                }
            } catch (DataIntegrityViolationException ex){
                log.warn("DataIntegrityViolationException while creating webapp for {} ", url);
            }
        }
    }


    @SafeVarargs
    private static <T> Predicate<T> distinctByKeys(Function<? super T, ?>... keyExtractors)
    {
        final Map<List<?>, Boolean> seen = new ConcurrentHashMap<>();

        return t ->
        {
            final List<?> keys = Arrays.stream(keyExtractors)
                    .map(ke -> ke.apply(t))
                    .collect(Collectors.toList());

            return seen.putIfAbsent(keys, Boolean.TRUE) == null;
        };
    }
}
