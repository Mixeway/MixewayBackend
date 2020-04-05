<a name="1.2.1"></a>
## 1.2.1 (2020-04-05)

### Info

* Endpoints for drawing OpenSource Vulnerabilities statistic within whole database context

<a name="1.2.0"></a>
## 1.2.0 (2020-04-02)

### Info

* Burp Enterprise Edition plugin
* WebApp Scan limits
* Offline risk calculation so loading of dashboard wont be lasting so much time

<a name="1.1."></a>
## 1.1.0 (2020-03-20)

### Info

* Redesigned model for Fortify Plugin (including usage of MixewayFortifyScaRestApi)
* Redesigned model for managing CI Operations, new fields and statuses
* New REST API endpoints for interaction with CI/CD tools (CIOperations endpoint)
* CodeVulns downloaded from Fortify SSC no longer contains description with code snipped due to performance issues


<a name="1.0.1"></a>
## 1.0.1 (2020-03-11)

### Info

* Edit method of editCodeProject REST API now can process of changing branch
* WebApp DAST controller now properly sanitize regex for UUID and other strings


<a name="1.0.0"></a>
## 1.0.0 (2020-02-08)

### Info

* Fixed vulnerabilities and bugs
* Vault integration is now optional however no integration will cause password to be stored in plain text

<a name="0.9.2"></a>
## 0.9.2 (2020-02-08)

### Info

* Fixed bug related with deletion of scanners
* REST API to get scanner types already integrated
* Checkmarx integration (scope: create project, configure scan, run sca, get vulnerabilities)
* Extended Fortify SSC integration - possibility to create and configure SSC projects via Mixeway

<a name="0.9.1"></a>
## 0.9.1 (2020-01-14)

### Info

* Fixed bug with Network scan request API
* Added possibility to put CRON expresion to DB and load if from DB
* Fixed some minnor bugs

<a name="0.9"></a>
## 0.9 (2019-12-07)

### Info

* Initial release
