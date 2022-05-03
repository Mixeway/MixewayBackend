<a href="/Mixeway/MixewayBackend/blob/master/CHANGELOG.md"><img src="https://camo.githubusercontent.com/452f81a1e660cf8f9a47db9405ce06a0f216221b/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f2d6368616e67656c6f672d626c75652e737667" alt="https://img.shields.io/badge/-changelog-blue.svg" data-canonical-src="https://img.shields.io/badge/-changelog-blue.svg" style="max-width:100%;"></a>
<a href="hub.docker.comd"><img src="https://img.shields.io/docker/pulls/mixeway/backend?logo=Mixeway&style=plastic" alt="https://img.shields.io/badge/-changelog-blue.svg" data-canonical-src="https://img.shields.io/badge/-changelog-blue.svg" style="max-width:100%;"></a>
![](https://github.com/Mixeway/MixewayBackend/workflows/Deploy%20prod%20version/badge.svg?branch=master)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Mixeway_MixewayBackend&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mixeway_MixewayBackend)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Mixeway_MixewayBackend&metric=security_rating)](https://sonarcloud.io/dashboard?id=Mixeway_MixewayBackend)

# Mixeway Backend <img src="https://mixeway.github.io/img/logo_dashboard.png" height="60px">

### About Mixeway:
Mixeway is an OpenSource software that is meant to simplify the process of security assurance of projects which are implemented using CICD procedures. **Mixawey is not another vulnerability scanning
software - it is security orchestration tool**.


With number of plugins for Vulnerability Scanners :
<img src="https://mixeway.github.io/img/nessus.png" height="50px">
<img src="https://mixeway.github.io/img/openvas.jpg" height="50px">
<img src="https://mixeway.github.io/img/acunetix.jpg" height="50px">
<img src="https://mixeway.github.io/img/fortify.jpg" height="50px">
<img src="https://mixeway.github.io/img/deptrack.png" height="50px">
<img src="https://mixeway.github.io/img/cis.png" height="50px">
<img src="https://mixeway.github.io/img/jenkins.jpg" height="50px">
<img src="https://mixeway.github.io/img/jira.jpg" height="50px">

With all this available, Mixeway provides functionalities to:
- Automatic service discovery (IaaS Plugin for assets and network scans for services)
- Automatic Vulnerability Scan Configuration (Based on most recent configuration) - hands-free!
- Automatic and on-demand Vulnerability scan execution (based on policy and executed via a REST API call)
- One Vulnerability Database for all type of sources - SAST, DAST, OpenSource and Infrastructure vulnerabilities in one place
- Customizable Security Quality Gateway - a reliable piece of information for CICD to decide if a job should pass or not.
- REST API enables integration with already used Vulnerability Management systems used within the organization.

Elements of a system:
- <a href="https://github.com/Mixeway/MixewayBackend">Backend - Spring Boot REST API</a>
- <a href="https://github.com/Mixeway/MixewayFrontend">Frontend - Angular 8 application </a>
- <a href="https://hub.docker.com/_/postgres">DB - postgres database</a>
- <a href="https://www.vaultproject.io/">Vault - password store</a>
- <a href="https://github.com/Mixeway/MixewayHub">MixewayHub - parent project which contain docker-compose and one click instalation </a>

###### Mixeway Backend Description:
Mixeway Backend is a spring boot application that serves REST API both for UserInterface and independent tools for scan creation and runs.
Backend application also contains vulnerability scanner plugins definitions. Each plugin contains at least 3 operations: configure scan,
run scan and load vulnerabilities. This allows mixeway to be completely in charge of the scanning process which allows it to completely
automize the vulnerability assessment process.

With Hashicorp Vault integration passwords for each security scanner (which is the most sensitive component) is properly secured.

<a href="https://mixeway.io">High level informations can be found here</a>

<a href="https://mixeway.github.io">More detailed and technical docs are here</a>

###### Hashicorp Vault integration:
Mixeway has to be able to reuse given passwords and api keys in order to use them with Vulnerability Scanning interactions.

**Vault integration is optional but it is strongly recommended to be included - otherwise password for vulnerability scanners will
be stored in plaintext.**

###### Mixeway User Interface Tech stack:
<img src="https://mixeway.github.io/img/spring.jpg" height="50px">
<img src="https://mixeway.github.io/img/postgres.jpg" height="50px">
<img src="https://mixeway.github.io/img/vault.jpg" height="50px">
<img src="https://mixeway.github.io/img/docker.png" height="50px">

###### Requirements:
- Running and working DB 
- JAVA 1.8
- SSL Certificates

###### Good to have:
- Hashicorp Vault up and running

###### Running in development mode:
1. Make sure DB is up and running (You can use guide how to use postgres docker here https://hub.docker.com/_/postgres)
2. Optionally make sure Vault is up and running (You can use guide how to use Vault docker here https://hub.docker.com/_/vault)
3. Generate certificates and convert them to PKCS12 (yes certificates are required even in dev)
```$xslt
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
```
```$xslt
openssl pkcs12 -inkey key.pem -in certificate.pem -export -out certificate.p12
```
CACERTS file is also needed, make sure You have known the location of it. <a href="https://stackoverflow.com/a/11937940/1394504">It can be found using tips here</a> 

Finnaly run
```
java -jar --server.ssl.trust-store=/etc/pki/cacerts \
          --server.ssl.trust-store-password=changeit \
          --server.ssl.key-store=/etc/pki/localhost.p12 \
          --server.ssl.key-store-password=changeit \
          --server.ssl.keyAlias=localhost \
          --spring.profiles.active=dev \
          --spring.datasource.url=jdbc:postgresql://127.0.0.1:5432/mixer \
          --spring.datasource.username=mixewayuser \
          --spring.datasource.password=mixewaypassword \
          --spring.cloud.vault.token=ffffffff-ffff-ffff-ffff-ffffffffffff \
          --spring.cloud.vault.scheme=http \
          --spring.cloud.vault.port=8200 \
          --spring.cloud.vault.host=MixerVault
```
 REST API will be exposed on port `:8443`

## Auth methods
Mixeway supports multiple authentication methods:

* GitHub OAuth
* Facebook OAuth
* Keycloak OAuth
* x509 Smart Cards

### GitHub OAuth
In order to enable GitHub OAuth make sure to properly register mixeway application at GitHub and then set variable:

* `GITHUB_APP_ID`
* `GITHUB_SECRET`

### Facebook SSO
In order to enable Facebook OAuth make sure to properly register mixeway application at Facebook and then set variable:

* `FACEBOOK_APP_ID`
* `FACEBOOK_SECRET`

### Keycloak SSO
In order to enable Facebook OAuth make sure to properly register mixeway application at Facebook and then set variable:

* `KEYCLOAK_REALM`
* `KEYCLOAK_URL` (ending with `/auth`)
* `KEYCLOAK_CLIENT_ID`
* `KEYCLOAK_SECRET`xq
* `KEYCLOAK_AUTH_ROLE`
* 