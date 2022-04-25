package io.mixeway.api.admin.controller;

import io.mixeway.api.admin.model.*;
import io.mixeway.api.admin.service.AdminSettingsRestService;
import io.mixeway.db.entity.*;
import io.mixeway.utils.Status;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.security.Principal;
import java.util.List;

@RestController()
@RequestMapping("/v2/api/admin")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AdminSettingsRestController {
    private final AdminSettingsRestService adminSettingsRestService;

    public AdminSettingsRestController(AdminSettingsRestService adminSettingsRestService){
        this.adminSettingsRestService = adminSettingsRestService;
    }


    /**
     * Endpoint Get settings of mixeway
     *
     * @return settings entity
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Settings returned"),
//            @ApiResponse(code = 417, message = "Unknown problem - should not happen")
//    })
//    @ApiOperation(value = "Get Global settings",
//            notes = "Returned settings configuration for Mixeway")
    @GetMapping(value = "/settings")
    public ResponseEntity<Settings> getSettings()  {
        return adminSettingsRestService.getSettings();
    }

    /**
     * Endpoint which update SMTP settings
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Settings updated"),
//            @ApiResponse(code = 417, message = "Unknown problem - should not happen")
//    })
//    @ApiOperation(value = "Update SMTP Settings",
//            notes = "Update SMTP settings which are required to be able to send e-mails")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/settings/smtp")
    public ResponseEntity<Status> updateSmtpSettings(@RequestBody SmtpSettingsModel smtpSettingsModel, Principal principal)  {
        return adminSettingsRestService.updateSmtpSettings(smtpSettingsModel, principal.getName());
    }

    /**
     * Endpoint which update Auth settings
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Settings updated"),
//            @ApiResponse(code = 417, message = "Unknown problem - should not happen")
//    })
//    @ApiOperation(value = "Update Auth settings",
//            notes = "Enable or disable options like: password auth, x509 auth, github auth or facebook auth")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/settings/auth")
    public ResponseEntity<Status> updateAuthSettings(@RequestBody AuthSettingsModel authSettingsModel, Principal principal)  {
        return adminSettingsRestService.updateAuthSettings(authSettingsModel, principal.getName());
    }

    /**
     * Endpoint create new routing domain entity
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 201, message = "Routing domain created"),
//            @ApiResponse(code = 417, message = "Name already exists")
//    })
//    @ApiOperation(value = "Create new Routing Domain",
//            notes = "Create new Routing domain. Routing domains are used to define which scanner has to perform action")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/settings/routingdomain")
    public ResponseEntity<Status> createRoutingDomain(@RequestBody RoutingDomain routingDomain, Principal principal)  {
        return adminSettingsRestService.createRoutingDomain(routingDomain, principal.getName());
    }

    /**
     * Endpoint delete routing domain by ID
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Routing domain deleted"),
//            @ApiResponse(code = 417, message = "Name already exists")
//    })
//    @ApiOperation(value = "Delete Routing Domain",
//            notes = "Delete Routing Domain by ID")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @DeleteMapping(value = "/settings/routingdomain/{routingDomainId}")
    public ResponseEntity<Status> deleteRoutingDomain(@PathVariable("routingDomainId") Long routingDomainId, Principal principal)  {
        return adminSettingsRestService.deleteRoutingDomain(routingDomainId, principal.getName());
    }

    /**
     * Endpoint create new proxy entity
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 201, message = "Proxy created"),
//            @ApiResponse(code = 417, message = "Name already exists")
//    })
//    @ApiOperation(value = "Create Proxy",
//            notes = "Create proxy. Proxies are used to properly access scanner")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/settings/proxy")
    public ResponseEntity<Status> createProxy(@RequestBody Proxies proxies, Principal principal)  {
        return adminSettingsRestService.createProxy(proxies, principal.getName());
    }

    /**
     * Endpoint delete proxy by ID
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Proxy deleted"),
//            @ApiResponse(code = 417, message = "Unknown error (problably linking)")
//    })
//    @ApiOperation(value = "Delete Proxy",
//            notes = "Delete proxy by ID")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @DeleteMapping(value = "/settings/proxy/{proxyId}")
    public ResponseEntity<Status> deleteProxy(@PathVariable("proxyId") Long proxyId, Principal principal)  {
        return adminSettingsRestService.deleteProxy(proxyId, principal.getName());
    }

    /**
     * Endpoint generate new master API Key
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 201, message = "API Key created"),
//            @ApiResponse(code = 417, message = "Error")
//    })
//    @ApiOperation(value = "Generate Master API Key",
//            notes = "Generate master API Key - master API key has Admin permission and can be used to access any API")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/settings/apikey/generate")
    public ResponseEntity<Status> generateApiKey(Principal principal)  {
        return adminSettingsRestService.generateApiKey(principal.getName());
    }

    /**
     * Delete API key and remove access
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "API Key deleted"),
//            @ApiResponse(code = 417, message = "Name already exists")
//    })
//    @ApiOperation(value = "Delete Master API Key",
//            notes = "Delete Master API Key - all access will be revoked")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @DeleteMapping(value = "/settings/apikey")
    public ResponseEntity<Status> deleteApiKey( Principal principal)  {
        return adminSettingsRestService.deleteApiKey(principal.getName());
    }

    /**
     * Set Value for Infrastructure auto scan with CRON expression
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Value set"),
//            @ApiResponse(code = 417, message = "Not valid Cron expression")
//    })
//    @ApiOperation(value = "Change CRON for Infrastructure scan",
//            notes = "Change CRON for Infrastructure scan, project with auto infra scan will be scanned with this")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PatchMapping(value = "/settings/infracron")
    public ResponseEntity<Status> changeInfraCron( Principal principal, @RequestBody CronSettings cronSettings)  {
        return adminSettingsRestService.changeInfraCron(principal.getName(), cronSettings);
    }

    /**
     * Set Value for WebApps auto scan with CRON expression
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Value set"),
//            @ApiResponse(code = 417, message = "Not valid Cron expression")
//    })
//    @ApiOperation(value = "Change CRON for WebApp scan",
//            notes = "Change CRON for WebAoo scan, project with auto webapp scan will be scanned with this")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PatchMapping(value = "/settings/webappcron")
    public ResponseEntity<Status> changeWebAppCron( Principal principal,@RequestBody CronSettings cronSettings)  {
        return adminSettingsRestService.changeWebAppCron(principal.getName(), cronSettings);
    }

    /**
     * Set Value for Source Code auto scan with CRON expression
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Value set"),
//            @ApiResponse(code = 417, message = "Not valid Cron expression")
//    })
//    @ApiOperation(value = "Change CRON for Code scan",
//            notes = "Change CRON for Code scan, project with auto code scan will be scanned with this")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PatchMapping(value = "/settings/codecron")
    public ResponseEntity<Status> changeCodeCron( Principal principal,@RequestBody CronSettings cronSettings)  {
        return adminSettingsRestService.changeCodeCron(principal.getName(), cronSettings);
    }

    /**
     * Set Value for Trend emial report with CRON expression
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Value set"),
//            @ApiResponse(code = 417, message = "Not valid Cron expression")
//    })
//    @ApiOperation(value = "Change CRON for Trend report",
//            notes = "If SMTP and trend emails are set this cron set value when reports are send ")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PatchMapping(value = "/settings/trendcron")
    public ResponseEntity<Status> changeTrendCron( Principal principal,@RequestBody CronSettings cronSettings)  {
        return adminSettingsRestService.changeTrendCron(principal.getName(), cronSettings);
    }

    /**
     * Set Value for Web APp scan strategy
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Value set"),
//            @ApiResponse(code = 417, message = "Expectation failed")
//    })
//    @ApiOperation(value = "Web App Scan Strategy",
//            notes = "Create strategy for webapp scans - required when You have many types of WebApp scanners in single Routing Domain")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PatchMapping(value = "/settings/webappscanstrategy")
    public ResponseEntity<Status> changeWebAppStrategy( Principal principal,@RequestBody @Valid WebAppScanStrategyModel webAppScanStrategyModel)  {
        return adminSettingsRestService.changeWebAppStrategy(principal.getName(), webAppScanStrategyModel);
    }

    /**
     * Get current Web App Scan Strategy
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Strategy returned")
//    })
//    @ApiOperation(value = "Get WebApp Scan strategy",
//            notes = "Get Details of WebApp Scan strategy")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/settings/webappscanstrategy")
    public ResponseEntity<WebAppScanStrategy> getWebAppStrategies()  {
        return adminSettingsRestService.getWebAppStrategies();
    }

    /**
     * Set value for Vuln Auditor integration settings
     *
     * @return status
     */
//    @ApiOperation(value = "Set integration with Vuln Auditor",
//            notes = "Enable or disable integration with Vuln Auditor as well as provide location information")
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "updated"),
//            @ApiResponse(code = 417, message = "Problem with request")
//    })
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PostMapping(value = "/settings/vulnauditor")
    public ResponseEntity<Status> updateVulnAuditorSettings(@RequestBody @Valid VulnAuditorEditSettings vulnAuditorSettings, Principal principal)  {
        return adminSettingsRestService.updateVulnAuditorSettings(vulnAuditorSettings, principal.getName());
    }

    /**
     * Get info about VulnAuditor integration
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Return value")
//    })
//    @ApiOperation(value = "Get Vuln Auditor integration info",
//            notes = "Get Vuln Auditor integration info")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/settings/vulnauditor")
    public ResponseEntity<VulnAuditorEditSettings> getVulnAuditorSettings()  {
        return adminSettingsRestService.getVulnAuditorSettings();
    }

    /**
     * Update Settings for Security Quality Gateway
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Value Updated"),
//            @ApiResponse(code = 417, message = "Request not valid")
//    })
//    @ApiOperation(value = "Update Security Quality Gateway Settings",
//            notes = "Update Security Quality Gateway Settings. It is used to define how grade for particular change will be calculated")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PostMapping(value = "/settings/securitygateway")
    public ResponseEntity<Status> updateSecurityGatewaySettings(Principal principal, @Valid @RequestBody SecurityGateway securityGateway)  {
        return adminSettingsRestService.updateSecurityGatewaySettings(principal.getName(), securityGateway);
    }

    /**
     * GetSecurity Quality Gateway configuration
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Value returned")
//    })
//    @ApiOperation(value = "Get Security Quality Gateway Settings",
//            notes = "Get details of security quality gateway settings")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/settings/securitygateway")
    public ResponseEntity<SecurityGateway> getSecurityGatewaySettings()  {
        return adminSettingsRestService.getSecurityGatewaySettings();
    }


    /**
     * Get Configuration for git credentials
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Value returned")
//    })
//    @ApiOperation(value = "Get Configuration for git credentials",
//            notes = "List of Git instances with predefined credentials")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/settings/gitcredentials")
    public ResponseEntity<List<GitCredentials>> getGitCredentials()  {
        return adminSettingsRestService.getGitCredentials();
    }

    /**
     * Add new Git credentials configuration
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Value returned"),
//            @ApiResponse(code = 400, message = "Bad Request")
//    })
//    @ApiOperation(value = "Add new Git credentials configuration",
//            notes = "Add predefined credentials for particular Git instance")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/settings/gitcredentials")
    public ResponseEntity<Status> addGitCredentials(@RequestBody GitCredentials gitCredentials, Principal principal)  {
        return adminSettingsRestService.addGitCredentials(gitCredentials, principal.getName());
    }


    /**
     * Edit git credentials
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Value returned"),
//            @ApiResponse(code = 400, message = "Bad Request")
//    })
//    @ApiOperation(value = "Edit git credentials",
//            notes = "Edit git credentials, editing url, username, password in any combination")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PostMapping(value = "/settings/gitcredentials/{id}")
    public ResponseEntity<Status> editGitCredentials(@PathVariable("id") Long id, @RequestBody GitCredentials gitCredentials, Principal principal)  {
        return adminSettingsRestService.editGitCredentials(id, gitCredentials, principal.getName());
    }
    /**
     * Delete git credentials
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Value returned"),
//            @ApiResponse(code = 400, message = "Bad Request")
//    })
//    @ApiOperation(value = "Delete git credentials",
//            notes = "Delete git credentials")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @DeleteMapping(value = "/settings/gitcredentials/{id}")
    public ResponseEntity<Status> deleteGitCredentials(@PathVariable("id") Long id, Principal principal)  {
        return adminSettingsRestService.deleteGitCredentials(id, principal.getName());
    }


}
