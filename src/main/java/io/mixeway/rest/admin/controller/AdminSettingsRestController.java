package io.mixeway.rest.admin.controller;

import io.mixeway.rest.admin.model.SmtpSettingsModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import io.mixeway.db.entity.Proxies;
import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.db.entity.Settings;
import io.mixeway.pojo.Status;
import io.mixeway.rest.admin.model.AuthSettingsModel;
import io.mixeway.rest.admin.service.AdminSettingsRestService;

import java.security.Principal;

@RestController()
@RequestMapping("/v2/api/admin")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AdminSettingsRestController {
    private final AdminSettingsRestService adminSettingsRestService;

    @Autowired
    public AdminSettingsRestController(AdminSettingsRestService adminSettingsRestService){
        this.adminSettingsRestService = adminSettingsRestService;
    }


    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/settings")
    public ResponseEntity<Settings> getSettings()  {
        return adminSettingsRestService.getSettings();
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/settings/smtp")
    public ResponseEntity<Status> updateSmtpSettings(@RequestBody SmtpSettingsModel smtpSettingsModel, Principal principal)  {
        return adminSettingsRestService.updateSmtpSettings(smtpSettingsModel, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/settings/auth")
    public ResponseEntity<Status> updateAuthSettings(@RequestBody AuthSettingsModel authSettingsModel, Principal principal)  {
        return adminSettingsRestService.updateAuthSettings(authSettingsModel, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/settings/routingdomain")
    public ResponseEntity<Status> createRoutingDomain(@RequestBody RoutingDomain routingDomain, Principal principal)  {
        return adminSettingsRestService.createRoutingDomain(routingDomain, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @DeleteMapping(value = "/settings/routingdomain/{routingDomainId}")
    public ResponseEntity<Status> deleteRoutingDomain(@PathVariable("routingDomainId") Long routingDomainId, Principal principal)  {
        return adminSettingsRestService.deleteRoutingDomain(routingDomainId, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/settings/proxy")
    public ResponseEntity<Status> createProxy(@RequestBody Proxies proxies, Principal principal)  {
        return adminSettingsRestService.createProxy(proxies, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @DeleteMapping(value = "/settings/proxy/{proxyId}")
    public ResponseEntity<Status> deleteProxy(@PathVariable("proxyId") Long proxyId, Principal principal)  {
        return adminSettingsRestService.deleteProxy(proxyId, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/settings/apikey/generate")
    public ResponseEntity<Status> generateApiKey(Principal principal)  {
        return adminSettingsRestService.generateApiKey(principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @DeleteMapping(value = "/settings/apikey")
    public ResponseEntity<Status> deleteApiKey( Principal principal)  {
        return adminSettingsRestService.deleteApiKey(principal.getName());
    }
}