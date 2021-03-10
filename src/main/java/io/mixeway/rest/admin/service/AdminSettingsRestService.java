package io.mixeway.rest.admin.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.scanner.VerifyWebAppScannerService;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.admin.model.*;
import org.apache.commons.lang3.StringUtils;
import org.quartz.CronExpression;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import io.mixeway.pojo.Status;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * @author gsiewruk
 */
@Service
public class AdminSettingsRestService {
    private final SettingsRepository settingsRepository;
    private final VaultHelper vaultHelper;
    private final RoutingDomainRepository routingDomainRepository;
    private final ProxiesRepository proxiesRepository;
    private final WebAppScanStrategyRepository webAppScanStrategyRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final VerifyWebAppScannerService verifyWebAppScannerService;
    private final SecurityGatewayRepository securityGatewayRepository;
    private final GitCredentialsRepository gitCredentialsRepository;
    private static final Logger log = LoggerFactory.getLogger(AdminSettingsRestService.class);


    public AdminSettingsRestService(SettingsRepository settingsRepository, VaultHelper vaultHelper, WebAppScanStrategyRepository webAppScanStrategyRepository,
                                    RoutingDomainRepository routingDomainRepository, ProxiesRepository proxiesRepository, SecurityGatewayRepository securityGatewayRepository,
                                    ScannerTypeRepository scannerTypeRepository, VerifyWebAppScannerService verifyWebAppScannerService,
                                    GitCredentialsRepository gitCredentialsRepository){
        this.settingsRepository = settingsRepository;
        this.vaultHelper = vaultHelper;
        this.securityGatewayRepository = securityGatewayRepository;
        this.scannerTypeRepository = scannerTypeRepository;
        this.proxiesRepository = proxiesRepository;
        this.webAppScanStrategyRepository = webAppScanStrategyRepository;
        this.routingDomainRepository = routingDomainRepository;
        this.verifyWebAppScannerService = verifyWebAppScannerService;
        this.gitCredentialsRepository = gitCredentialsRepository;
    }

    public ResponseEntity<Settings> getSettings() {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        return settings.map(value -> new ResponseEntity<>(value, HttpStatus.OK)).orElseGet(() -> new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED));
    }

    public ResponseEntity<Status> updateSmtpSettings(SmtpSettingsModel smtpSettingsModel, String name) {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent()){
            Settings settingsToUpdate = settings.get();
            if (smtpSettingsModel.getSmtpAuth() && smtpSettingsModel.getSmtpPassword()!=null && smtpSettingsModel.getSmtpUsername()!=null){
                settingsToUpdate.setSmtpAuth(smtpSettingsModel.getSmtpAuth());
                settingsToUpdate.setSmtpUsername(smtpSettingsModel.getSmtpUsername());
                settingsToUpdate.setDomain(smtpSettingsModel.getDomain());
                String uuidToken = UUID.randomUUID().toString();
                if (vaultHelper.savePassword(smtpSettingsModel.getSmtpPassword(),uuidToken)) {
                    settingsToUpdate.setSmtpPassword(uuidToken);
                } else {
                    settingsToUpdate.setSmtpPassword(smtpSettingsModel.getSmtpPassword());
                }
            } else if (smtpSettingsModel.getSmtpAuth() && (smtpSettingsModel.getSmtpPassword()!=null || smtpSettingsModel.getSmtpUsername()!=null) ){
                return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
            }
            settingsToUpdate.setSmtpHost(smtpSettingsModel.getSmtpHost());
            settingsToUpdate.setSmtpPort(smtpSettingsModel.getSmtpPort());
            settingsToUpdate.setSmtpTls(smtpSettingsModel.getSmtpTls());
            settingsRepository.save(settingsToUpdate);
            log.info("{} - Updated SMTP settings", name);
            return new ResponseEntity<>( HttpStatus.OK);
        } else {
            return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> updateAuthSettings(AuthSettingsModel authSettingsModel, String name) {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent() && (authSettingsModel.getCertificateAuth() || authSettingsModel.getPasswordAuth())){
            Settings settingsToUpdate = settings.get();
            settingsToUpdate.setPasswordAuth(authSettingsModel.getPasswordAuth());
            settingsToUpdate.setCertificateAuth(authSettingsModel.getCertificateAuth());
            settingsRepository.save(settingsToUpdate);
            log.info("{} - Updated auth settings}", name);
            return new ResponseEntity<>(HttpStatus.OK);

        } else {
            return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> createRoutingDomain(RoutingDomain routingDomain, String name) {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent() && routingDomain.getName()!=null){
            routingDomainRepository.save(routingDomain);
            log.info("{} - Created new routing domain {}", name, LogUtil.prepare(routingDomain.getName()));
            return new ResponseEntity<>(HttpStatus.CREATED);

        } else {
            return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> deleteRoutingDomain(Long routingDomainId, String name) {
        Optional<RoutingDomain> routingDomain = routingDomainRepository.findById(routingDomainId);
        if (routingDomain.isPresent()){
            try {
                routingDomainRepository.delete(routingDomain.get());
                log.info("{} - Deleted routing domian {}", name, routingDomain.get().getName());
                return new ResponseEntity<>(HttpStatus.OK);
            } catch (Exception ex){
                return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
            }
        } else {
            return new ResponseEntity<>( HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<Status> createProxy(Proxies proxies, String name) {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent() && proxies.getIp()!=null && proxies.getPort() !=null && proxies.getDescription()!=null){
            proxiesRepository.save(proxies);
            log.info("{} - Created new proxy {} ", name, LogUtil.prepare(proxies.getIp())+":"+ LogUtil.prepare(proxies.getPort()));
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> deleteProxy(Long proxyId, String name) {
        Optional<Proxies> proxies = proxiesRepository.findById(proxyId);
        if (proxies.isPresent()){
            try {
                proxiesRepository.delete(proxies.get());
                log.info("{} - Deleted proxy {}", name, proxies.get().getIp());
                return new ResponseEntity<>(HttpStatus.OK);
            } catch (Exception e){
                return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
            }
        } else {
            return new ResponseEntity<>( HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<Status> generateApiKey(String name) {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent()){
            settings.get().setMasterApiKey(UUID.randomUUID().toString());
            settingsRepository.save(settings.get());
            log.info("{} - Generated new Master API Key", name);
            return new ResponseEntity<>(HttpStatus.CREATED);

        } else {
            return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> deleteApiKey(String name) {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent()){
            settings.get().setMasterApiKey(null);
            settingsRepository.save(settings.get());
            log.info("{} - Deleted Master API Key", name);
            return new ResponseEntity<>(HttpStatus.OK);

        } else {
            return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> changeInfraCron(String name, CronSettings cronSettings) {
        try {


            CronExpression cron = new CronExpression(cronSettings.getExpression());
            Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
            if (settings.isPresent()){
                settings.get().setInfraAutoCron(cronSettings.getExpression());
                settingsRepository.save(settings.get());
                log.info("{} - Changed Cron auto scan start for network to {} - {}", name, LogUtil.prepare(cronSettings.getExpression()), cron.getExpressionSummary());
                return new ResponseEntity<>( HttpStatus.OK);
            }
        } catch (ParseException e) {
            return new ResponseEntity<>(new Status(e.getLocalizedMessage()), HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> changeWebAppCron(String name, CronSettings cronSettings) {
        try {
            CronExpression cron = new CronExpression(cronSettings.getExpression());
            Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
            if (settings.isPresent()){
                settings.get().setWebAppAutoCron(cronSettings.getExpression());
                settingsRepository.save(settings.get());
                log.info("{} - Changed Cron auto scan start for WebApp to {}", name, cron.getExpressionSummary());
                return new ResponseEntity<>( HttpStatus.OK);
            }
        } catch (ParseException e) {
            return new ResponseEntity<>(new Status(e.getLocalizedMessage()), HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> changeCodeCron(String name, CronSettings cronSettings) {
        try {
            CronExpression cron = new CronExpression(cronSettings.getExpression());
            Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
            if (settings.isPresent()){
                settings.get().setCodeAutoCron(cronSettings.getExpression());
                settingsRepository.save(settings.get());
                log.info("{} - Changed Cron auto scan start for code to {}", name, cron.getExpressionSummary());
                return new ResponseEntity<>( HttpStatus.OK);
            }
        } catch (ParseException e) {
            return new ResponseEntity<>(new Status(e.getLocalizedMessage()), HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> changeTrendCron(String name, CronSettings cronSettings) {
        try {
            CronExpression cron = new CronExpression(cronSettings.getExpression());
            Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
            if (settings.isPresent()){
                settings.get().setTrendEmailCron(cronSettings.getExpression());
                settingsRepository.save(settings.get());
                log.info("{} - Changed Cron auto scan start for code to {}", LogUtil.prepare(name), cron.getExpressionSummary());
                return new ResponseEntity<>( HttpStatus.OK);
            }
        } catch (ParseException e) {
            return new ResponseEntity<>(new Status(e.getLocalizedMessage()), HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
    }

    @Transactional
    public ResponseEntity<Status> changeWebAppStrategy(String name, WebAppScanStrategyModel webAppScanStrategyModel) {
        WebAppScanStrategy webAppScanStrategy = webAppScanStrategyRepository.findAll().stream().findFirst().orElse(null);
        boolean error = false;
        if (webAppScanStrategy != null){
            if (webAppScanStrategyModel.getApiStrategy() != null){
                ScannerType apiStrategy = scannerTypeRepository.findByNameIgnoreCase(webAppScanStrategyModel.getApiStrategy());
                if (verifyWebAppScannerService.canSetPolicyForGivenScanner(apiStrategy))
                    webAppScanStrategy.setApiStrategy(apiStrategy);
                else
                    error=true;
            } else {
                webAppScanStrategy.setApiStrategy(null);
            }
            if (webAppScanStrategyModel.getScheduledStrategy() != null){
                ScannerType scheduledStrategy = scannerTypeRepository.findByNameIgnoreCase(webAppScanStrategyModel.getScheduledStrategy());
                if (verifyWebAppScannerService.canSetPolicyForGivenScanner(scheduledStrategy))
                    webAppScanStrategy.setScheduledStrategy(scheduledStrategy);
                else
                    error=true;
            } else {
                webAppScanStrategy.setScheduledStrategy(null);
            }
            if (webAppScanStrategyModel.getGuiStrategy() != null){
                ScannerType guiStrategy = scannerTypeRepository.findByNameIgnoreCase(webAppScanStrategyModel.getGuiStrategy());
                if (verifyWebAppScannerService.canSetPolicyForGivenScanner(guiStrategy))
                    webAppScanStrategy.setGuiStrategy(guiStrategy);
                else
                    error=true;
            } else {
                webAppScanStrategy.setGuiStrategy(null);
            }
        }
        if (error)
            return new ResponseEntity<>(HttpStatus.CONFLICT);
        else
            return new ResponseEntity<>(HttpStatus.OK);
    }

    public ResponseEntity<WebAppScanStrategy> getWebAppStrategies(String name) {
        WebAppScanStrategy webAppScanStrategy = webAppScanStrategyRepository.findAll().stream().findFirst().orElse(null);
        return new ResponseEntity<>(webAppScanStrategy, HttpStatus.OK);
    }

    public ResponseEntity<Status> updateVulnAuditorSettings(VulnAuditorEditSettings vulnAuditorSettings, String name) {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent()){
            settings.get().setVulnAuditorEnable(vulnAuditorSettings.isEnabled());
            settings.get().setVulnAuditorUrl(vulnAuditorSettings.getUrl());
            settingsRepository.save(settings.get());
            log.info("{} - Updated Vuln Auditor Settings - enabled {} url {}", LogUtil.prepare(name),
                    LogUtil.prepare(String.valueOf(vulnAuditorSettings.isEnabled())), LogUtil.prepare(vulnAuditorSettings.getUrl()));
            return new ResponseEntity<>( HttpStatus.OK);
        }
        return new ResponseEntity<>( HttpStatus.PRECONDITION_FAILED);
    }

    public ResponseEntity<VulnAuditorEditSettings> getVulnAuditorSettings(String name) {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent()){
            VulnAuditorEditSettings vulnAuditorEditSettings = new VulnAuditorEditSettings(settings.get());
            return new ResponseEntity<>(vulnAuditorEditSettings, HttpStatus.OK);
        }
        return new ResponseEntity<>( HttpStatus.PRECONDITION_FAILED);
    }

    @Transactional
    public ResponseEntity<Status> updateSecurityGatewaySettings(String name, SecurityGateway securityGatewayToUpdate) {
        SecurityGateway securityGateway = securityGatewayRepository.findAll().stream().findFirst().orElse(null);
        if (securityGateway != null){
            securityGateway.setGrade(securityGatewayToUpdate.isGrade());
            securityGateway.setCritical(securityGatewayToUpdate.getCritical());
            securityGateway.setHigh(securityGatewayToUpdate.getHigh());
            securityGateway.setMedium(securityGatewayToUpdate.getMedium());
            securityGateway.setVuln(securityGatewayToUpdate.getVuln());
            log.info("{} - Updated settings for Security Quality Gateway", LogUtil.prepare(name));
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<SecurityGateway> getSecurityGatewaySettings(String name) {
        SecurityGateway securityGateway = securityGatewayRepository.findAll().stream().findFirst().orElse(null);
        if (securityGateway != null){
            return new ResponseEntity<>(securityGateway, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<List<GitCredentials>> getGitCredentials(String name) {
        List<GitCredentials> gitCredentials = gitCredentialsRepository.findAll();
        gitCredentials.forEach(p->p.setPassword(Constants.DUMMY_PASSWORD));
        return new ResponseEntity<>( gitCredentials, HttpStatus.OK);
    }

    public ResponseEntity<Status> addGitCredentials(GitCredentials gitCredentials, String name) {
        Optional<GitCredentials> toVerifyCredentials = gitCredentialsRepository.findByUrl(gitCredentials.getUrl());
        if (toVerifyCredentials.isPresent()){
            return new ResponseEntity<>(new Status("Given URL already exists"), HttpStatus.PRECONDITION_FAILED);
        }
        if (StringUtils.isNotBlank(gitCredentials.getUrl()) &&
                StringUtils.isNotBlank(gitCredentials.getUsername()) &&
                StringUtils.isNotBlank(gitCredentials.getPassword())) {
            String repoPasswordToken = UUID.randomUUID().toString();
            if (vaultHelper.savePassword(gitCredentials.getPassword(),repoPasswordToken)){
                gitCredentials.setPassword(repoPasswordToken);
            }
            gitCredentialsRepository.save(gitCredentials);
            log.info("{}, created new GitCredentials entry for URL: {}, and user: {}", name, LogUtil.prepare(gitCredentials.getUrl())
                    ,LogUtil.prepare(gitCredentials.getUsername()));
            return new ResponseEntity<>(HttpStatus.CREATED);
        }
        return new ResponseEntity<>(new Status("All fields should be set"), HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity<Status> editGitCredentials(Long id, GitCredentials gitCredentials, String name) {
        Optional<GitCredentials> gitCredentialsToEdit = gitCredentialsRepository.findById(id);
        if (gitCredentialsToEdit.isPresent()){
            if (StringUtils.isNotBlank(gitCredentials.getUrl())){
                log.info("{} Editing entry for git credentials URL- old value: {}, new value {}",name,LogUtil.prepare(gitCredentialsToEdit.get().getUrl()), LogUtil.prepare(gitCredentials.getUrl()));
                gitCredentialsToEdit.get().setUrl(gitCredentials.getUrl());
            }
            if (StringUtils.isNotBlank(gitCredentials.getUsername())){
                log.info("{} Editing entry for git credentials USERNAME- old value: {}, new value {}",name,LogUtil.prepare(gitCredentialsToEdit.get().getUsername()), LogUtil.prepare(gitCredentials.getUsername()));
                gitCredentialsToEdit.get().setUsername(gitCredentials.getUsername());
            }
            if (StringUtils.isNotBlank(gitCredentials.getPassword()) && !gitCredentials.getPassword().equals(Constants.DUMMY_PASSWORD)){
                log.info("{} Editing entry for git credentials URL {} changing password.",name,LogUtil.prepare(gitCredentialsToEdit.get().getUrl()));
                String repoPasswordToken = UUID.randomUUID().toString();
                if (vaultHelper.savePassword(gitCredentials.getPassword(),repoPasswordToken)){
                    gitCredentialsToEdit.get().setPassword(repoPasswordToken);
                } else {
                    gitCredentialsToEdit.get().setPassword(gitCredentials.getPassword());
                }
            }
            gitCredentialsRepository.save(gitCredentialsToEdit.get());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    public ResponseEntity<Status> deleteGitCredentials(Long id, String name) {
        Optional<GitCredentials> gitCredentials = gitCredentialsRepository.findById(id);
        if (gitCredentials.isPresent()){
            gitCredentialsRepository.delete(gitCredentials.get());
            log.info("{} Deleted GitConfiguration for URL {}", name, gitCredentials.get().getUrl());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
}
