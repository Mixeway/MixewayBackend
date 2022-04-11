package io.mixeway.api.admin.service;

import io.mixeway.api.admin.model.*;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.domain.service.gitcredentials.CreateGitCredentialsService;
import io.mixeway.domain.service.gitcredentials.DeleteGitCredentialsService;
import io.mixeway.domain.service.gitcredentials.FindGitCredentialsService;
import io.mixeway.domain.service.gitcredentials.UpdateGitCredentialsService;
import io.mixeway.domain.service.proxy.DeleteProxyService;
import io.mixeway.domain.service.proxy.GetOrCreateProxyService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.domain.service.routingdomain.DeleteRoutingDomainService;
import io.mixeway.domain.service.routingdomain.FindRoutingDomainService;
import io.mixeway.domain.service.securitygateway.FindSecurityGatewayService;
import io.mixeway.domain.service.securitygateway.UpdateSecurityGatewayService;
import io.mixeway.domain.service.settings.GetSettingsService;
import io.mixeway.domain.service.settings.UpdateSettingsService;
import io.mixeway.domain.service.webappscanstrategy.FindWebAppScanStrategyService;
import io.mixeway.domain.service.webappscanstrategy.UpdateWebAppScanStrategyService;
import io.mixeway.utils.LogUtil;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.quartz.CronExpression;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@Log4j2
@RequiredArgsConstructor
public class AdminSettingsRestService {
    private final GetSettingsService getSettingsService;
    private final UpdateSettingsService updateSettingsService;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final FindRoutingDomainService findRoutingDomainService;
    private final DeleteRoutingDomainService deleteRoutingDomainService;
    private final GetOrCreateProxyService getOrCreateProxyService;
    private final DeleteProxyService deleteProxyService;
    private final FindWebAppScanStrategyService findWebAppScanStrategyService;
    private final UpdateWebAppScanStrategyService updateWebAppScanStrategyService;
    private final FindSecurityGatewayService findSecurityGatewayService;
    private final UpdateSecurityGatewayService updateSecurityGatewayService;
    private final FindGitCredentialsService findGitCredentialsService;
    private final CreateGitCredentialsService createGitCredentialsService;
    private final UpdateGitCredentialsService updateGitCredentialsService;
    private final DeleteGitCredentialsService deleteGitCredentialsService;

    public ResponseEntity<Settings> getSettings() {
        Optional<Settings> settings = Optional.ofNullable(getSettingsService.getSettings());
        return settings.map(value -> new ResponseEntity<>(value, HttpStatus.OK)).orElseGet(() -> new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED));
    }

    public ResponseEntity<Status> updateSmtpSettings(SmtpSettingsModel smtpSettingsModel, String name) {
        Settings settings = getSettingsService.getSettings();
        if (settings != null){
            updateSettingsService.updateSmtp(smtpSettingsModel,name, settings);
            log.info("{} - Updated SMTP settings", name);
            return new ResponseEntity<>( HttpStatus.OK);
        } else {
            return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> updateAuthSettings(AuthSettingsModel authSettingsModel, String name) {
        Settings settings = getSettingsService.getSettings();
        if (settings != null && (authSettingsModel.getCertificateAuth() || authSettingsModel.getPasswordAuth())){
            updateSettingsService.updateAuth(settings,authSettingsModel);
            log.info("{} - Updated auth settings}", name);
            return new ResponseEntity<>(HttpStatus.OK);

        } else {
            return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> createRoutingDomain(RoutingDomain routingDomain, String name) {
        Settings settings = getSettingsService.getSettings();
        if (settings != null && routingDomain.getName()!=null){
            createOrGetRoutingDomainService.createOrGetRoutingDomain(routingDomain.getName());
            log.info("{} - Created new routing domain {}", name, LogUtil.prepare(routingDomain.getName()));
            return new ResponseEntity<>(HttpStatus.CREATED);

        } else {
            return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> deleteRoutingDomain(Long routingDomainId, String name) {
        Optional<RoutingDomain> routingDomain = findRoutingDomainService.findById(routingDomainId);
        if (routingDomain.isPresent()){
            try {
                deleteRoutingDomainService.deleteById(routingDomainId);
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
        Settings settings = getSettingsService.getSettings();
        if (settings != null && proxies.getIp()!=null && proxies.getPort() !=null && proxies.getDescription()!=null){
            getOrCreateProxyService.getOrCreateProxies(proxies);
            log.info("{} - Created new proxy {} ", name, LogUtil.prepare(proxies.getIp())+":"+ LogUtil.prepare(proxies.getPort()));
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> deleteProxy(Long proxyId, String name) {
        Optional<Proxies> proxies = getOrCreateProxyService.findById(proxyId);
        if (proxies.isPresent()){
            try {
                deleteProxyService.deleteById(proxyId);
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
        Settings settings = getSettingsService.getSettings();
        if (settings != null){
            updateSettingsService.updateMasterApiKey(settings);
            log.info("{} - Generated new Master API Key", name);
            return new ResponseEntity<>(HttpStatus.CREATED);

        } else {
            return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> deleteApiKey(String name) {
        Settings settings = getSettingsService.getSettings();
        if (settings != null){
            updateSettingsService.deleteMasterApiKey(settings);
            log.info("{} - Deleted Master API Key", name);
            return new ResponseEntity<>(HttpStatus.OK);

        } else {
            return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> changeInfraCron(String name, CronSettings cronSettings) {
        try {
            CronExpression cron = new CronExpression(cronSettings.getExpression());
            Settings settings = getSettingsService.getSettings();
            if (settings != null){
                updateSettingsService.updateInfraCron(settings, cronSettings);
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
            Settings settings = getSettingsService.getSettings();
            if (settings != null){
                updateSettingsService.updateWebAppCron(settings, cronSettings);
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
            Settings settings = getSettingsService.getSettings();
            if (settings != null){
                updateSettingsService.updateCodeCron(settings, cronSettings);
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
            Settings settings = getSettingsService.getSettings();
            if (settings != null){
                updateSettingsService.updateTrendCron(settings, cronSettings);
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
        boolean error = updateWebAppScanStrategyService.canUpdateWebAppScanStrategy(webAppScanStrategyModel);
        log.info("[Admin] {} changed webapp scan strategy", name);
        if (error)
            return new ResponseEntity<>(HttpStatus.CONFLICT);
        else
            return new ResponseEntity<>(HttpStatus.OK);
    }

    public ResponseEntity<WebAppScanStrategy> getWebAppStrategies() {
        WebAppScanStrategy webAppScanStrategy = findWebAppScanStrategyService.findWebAppScanStrategy();
        return new ResponseEntity<>(webAppScanStrategy, HttpStatus.OK);
    }

    public ResponseEntity<Status> updateVulnAuditorSettings(VulnAuditorEditSettings vulnAuditorSettings, String name) {
        try {
            Settings settings = getSettingsService.getSettings();
            updateSettingsService.updateVulnAuditorSettings(settings, vulnAuditorSettings);
            log.info("{} - Updated Vuln Auditor Settings - enabled {} url {}", LogUtil.prepare(name),
                    LogUtil.prepare(String.valueOf(vulnAuditorSettings.isEnabled())), LogUtil.prepare(vulnAuditorSettings.getUrl()));
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (Exception e) {
            log.error("[Admin] Error during updating vuln auditor settings {}", e.getLocalizedMessage());
            return new ResponseEntity<>( HttpStatus.PRECONDITION_FAILED);
        }

    }

    public ResponseEntity<VulnAuditorEditSettings> getVulnAuditorSettings() {
        Settings settings = getSettingsService.getSettings();
        VulnAuditorEditSettings vulnAuditorEditSettings = new VulnAuditorEditSettings(settings);
        return new ResponseEntity<>(vulnAuditorEditSettings, HttpStatus.OK);
    }

    @Transactional
    public ResponseEntity<Status> updateSecurityGatewaySettings(String name, SecurityGateway securityGatewayToUpdate) {
        updateSecurityGatewayService.update(securityGatewayToUpdate);
        log.info("[Admin] Security Gateway updated by {}", name);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    public ResponseEntity<SecurityGateway> getSecurityGatewaySettings() {
        SecurityGateway securityGateway = findSecurityGatewayService.getSecurityGateway();
        if (securityGateway != null){
            return new ResponseEntity<>(securityGateway, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<List<GitCredentials>> getGitCredentials() {
        List<GitCredentials> gitCredentials = findGitCredentialsService.findAll();
        gitCredentials.forEach(p->p.setPassword(Constants.DUMMY_PASSWORD));
        return new ResponseEntity<>( gitCredentials, HttpStatus.OK);
    }

    public ResponseEntity<Status> addGitCredentials(GitCredentials gitCredentials, String name) {
        Optional<GitCredentials> toVerifyCredentials = findGitCredentialsService.findByUrl(gitCredentials.getUrl());
        if (toVerifyCredentials.isPresent()){
            return new ResponseEntity<>(new Status("Given URL already exists"), HttpStatus.PRECONDITION_FAILED);
        }
        if (StringUtils.isNotBlank(gitCredentials.getUrl()) &&
                StringUtils.isNotBlank(gitCredentials.getUsername()) &&
                StringUtils.isNotBlank(gitCredentials.getPassword())) {
            createGitCredentialsService.create(gitCredentials);
            log.info("[Admin] {}, created new GitCredentials entry for URL: {}, and user: {}", name, LogUtil.prepare(gitCredentials.getUrl())
                    ,LogUtil.prepare(gitCredentials.getUsername()));
            return new ResponseEntity<>(HttpStatus.CREATED);
        }
        return new ResponseEntity<>(new Status("All fields should be set"), HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity<Status> editGitCredentials(Long id, GitCredentials gitCredentials, String name) {
        Optional<GitCredentials> gitCredentialsToEdit = findGitCredentialsService.findById(id);
        if (gitCredentialsToEdit.isPresent()){
            if (StringUtils.isNotBlank(gitCredentials.getUrl())){
                log.info("{} Editing entry for git credentials URL- old value: {}, new value {}",name,LogUtil.prepare(gitCredentialsToEdit.get().getUrl()), LogUtil.prepare(gitCredentials.getUrl()));
                updateGitCredentialsService.updateUrl(gitCredentialsToEdit.get(), gitCredentials);
            }
            if (StringUtils.isNotBlank(gitCredentials.getUsername())){
                log.info("{} Editing entry for git credentials USERNAME- old value: {}, new value {}",name,LogUtil.prepare(gitCredentialsToEdit.get().getUsername()), LogUtil.prepare(gitCredentials.getUsername()));
                updateGitCredentialsService.updateUsername(gitCredentialsToEdit.get(), gitCredentials);
            }
            if (StringUtils.isNotBlank(gitCredentials.getPassword()) && !gitCredentials.getPassword().equals(Constants.DUMMY_PASSWORD)){
                log.info("{} Editing entry for git credentials URL {} changing password.",name,LogUtil.prepare(gitCredentialsToEdit.get().getUrl()));
                updateGitCredentialsService.updatePassword(gitCredentialsToEdit.get(), gitCredentials);
            }
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    public ResponseEntity<Status> deleteGitCredentials(Long id, String name) {
        Optional<GitCredentials> gitCredentials = findGitCredentialsService.findById(id);
        if (gitCredentials.isPresent()){
            deleteGitCredentialsService.remove(gitCredentials.get());
            log.info("{} Deleted GitConfiguration for URL {}", name, gitCredentials.get().getUrl());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
}
