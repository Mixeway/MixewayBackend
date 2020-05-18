package io.mixeway.pojo;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import io.mixeway.db.repository.WebAppRepository;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Component
public class WebAppHelper {
    private static final Logger log = LoggerFactory.getLogger(WebAppHelper.class);
    private InterfaceRepository interfaceRepository;
    private WebAppRepository webAppRepository;
    private VulnTemplate vulnTemplate;

    @Autowired
    WebAppHelper(VulnTemplate vulnTemplate, InterfaceRepository interfaceRepository,
                 WebAppRepository webAppRepository){
        this.interfaceRepository = interfaceRepository;
        this.webAppRepository = webAppRepository;
        this.vulnTemplate = vulnTemplate;
    }

    public void discoverWebAppFromInfrastructureVulns(Project project, NessusScan ns){
        List<Interface> interfaces = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        List<ProjectVulnerability> vulns = vulnTemplate.projectVulnerabilityRepository.getVulnsByInterfacesAndWithWWW(interfaces);
        List<ProjectVulnerability> uniqueWWW = vulns
                .stream()
                .filter(distinctByKeys(ProjectVulnerability::getAnInterface, ProjectVulnerability::getPort))
                .collect(Collectors.toList());
        createOrVerifyWebApps(project, uniqueWWW, ns);

    }
    public void createOrVerifyWebApps(Project project, List<ProjectVulnerability> vulns, NessusScan ns){
        for (ProjectVulnerability iv : vulns){
            String port = iv.getPort().split("/")[0].trim();
            String proto ="http://";
            if (port.endsWith("443")){
                proto="https://";
            }
            String url = proto+iv.getAnInterface().getPrivateip()+":"+port;
            Optional<WebApp> webApp = webAppRepository.findByUrl(url);
            try {
                if (!webApp.isPresent()) {
                    WebApp webAppToCreate = new WebApp();
                    webAppToCreate.setOrigin(Constants.STRATEGY_SCHEDULER);
                    webAppToCreate.setProject(project);
                    webAppToCreate.setUrl(url);
                    webAppToCreate.setRunning(false);
                    webAppToCreate.setAutoStart(true);
                    webAppToCreate.setRoutingDomain(ns.getNessus().getRoutingDomain());
                    webAppToCreate.setPublicscan(iv.getAnInterface().getRoutingDomain().getName().equals("Internet"));
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
