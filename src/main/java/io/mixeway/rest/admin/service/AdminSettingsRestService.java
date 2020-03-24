package io.mixeway.rest.admin.service;

import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.admin.model.CronSettings;
import io.mixeway.rest.admin.model.SmtpSettingsModel;
import org.quartz.CronExpression;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import io.mixeway.db.entity.Proxies;
import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.repository.ProxiesRepository;
import io.mixeway.db.repository.RoutingDomainRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.pojo.Status;
import io.mixeway.rest.admin.model.AuthSettingsModel;
import sun.rmi.runtime.Log;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class AdminSettingsRestService {
    private final SettingsRepository settingsRepository;
    private final VaultHelper vaultHelper;
    private final RoutingDomainRepository routingDomainRepository;
    private final ProxiesRepository proxiesRepository;
    private static final Logger log = LoggerFactory.getLogger(AdminSettingsRestService.class);


    public AdminSettingsRestService(SettingsRepository settingsRepository, VaultHelper vaultHelper,
                                    RoutingDomainRepository routingDomainRepository, ProxiesRepository proxiesRepository){
        this.settingsRepository = settingsRepository;
        this.vaultHelper = vaultHelper;
        this.proxiesRepository = proxiesRepository;
        this.routingDomainRepository = routingDomainRepository;
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
                log.info("{} - Changed Cron auto scan start for network to {}", name, LogUtil.prepare(cronSettings.getExpression()));
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
                log.info("{} - Changed Cron auto scan start for WebApp to {}", name, LogUtil.prepare(cronSettings.getExpression()));
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
                log.info("{} - Changed Cron auto scan start for code to {}", name, LogUtil.prepare(cronSettings.getExpression()));
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
                log.info("{} - Changed Cron auto scan start for code to {}", LogUtil.prepare(name), LogUtil.prepare(cronSettings.getExpression()));
                return new ResponseEntity<>( HttpStatus.OK);
            }
        } catch (ParseException e) {
            return new ResponseEntity<>(new Status(e.getLocalizedMessage()), HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>( HttpStatus.EXPECTATION_FAILED);
    }
}
