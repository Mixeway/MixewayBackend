## 1.8.3 (2024-03-20)

#### New Features
* Restored integration with MixewayVulnerabilityAuditor

#### Bug Fixes
* Fixed bug that prevents dependency track vulnerabilities to being loaded
* Fixed bug stacktrace errors complaining about missing column password in table bugtracker
* Fixed bug with nexus-iq integration that detect vulnerabilities in null:null packages

## 1.8.0 (2023-08-08)

#### New Features
* Enabled hibernate envers for projectvulnerability table
* added endpoint with more detailed statistics for both project and vulnerabilities discovered within project

#### Bug Fixes
* Fixed bug when some vulnerabilities status was not managed properly
* Fixed bug with Checkmarx integration

## 1.7.2 (19.06.2023)

### New Features
* Added ZAP DAST scanner integration

## 1.7.1 (2023-01-23)

#### New Features
* New API and methods to show simplified statistic page

## 1.7.0 (2023-01-23)

#### Bug Fixes
* Fixed bug with ambitious responses from requesting infrastructure scan
* Fixed bug with caused sometimes failure in creating synchronization with SCA

#### New Features
* Nexus-IQ Integration


## 1.6.3 (2022-07-28)

#### Bug Fixes
* Fixing Checkmarx integration

#### New Features
* Adding global statistics for admin acceess


## 1.6.1 (2022-05-07)

#### Bug Fixes
* Fixed bug that allow to perform multiple sast scans of same project. Fixed status management, now when specific codeproject has inqueue or running state equal to true, it cannot be put on queue



<a name="1.3.0"></a>
## 1.3.0 (2020-05-31)

#### New Features

* Mixeway Vuln Auditor - DeepLearning microservice which use Neural Network to classify software vulnerabilities
* Vulnerability Description is displayed in more proper manner. Modal displaying details is allowing user to confirm or
deny vulnerability
* Possibility to create Application profile, on both project or asset level information gathered and put into profile
helps Vuln Auditor to better understand application context and then classify vulnerability

#### Bug Fixes
* Tables filtering set to proper level. Whenever possible select fields are possible to show.
* Vulnerabilities are no longer deleted before loading from scanner. ID of detected vulnerability is constant, vulnerability is deleted
only if it is not detected in next scan.

#### Removed Features
* Partitioning software vulnerabilities was removed, in this place single tab is displayed with colum which allows to filter


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
