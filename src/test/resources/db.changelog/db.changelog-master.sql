--liquibase formatted sql

--changeset siewer:3
create table project(
  id serial primary key,
  name text,
  description text);

--changeset siewer:4
create table iaasapi(
  id serial primary key,
  iamurl text,
  serviceurl text,
  networkurl text,
  project_id int references project(id));

--changeset siewer:5
alter table iaasapi add column domain text;
alter table iaasapi add column username text;
alter table iaasapi add column password text;
alter table iaasapi add column tenantid text;

--changeset siewer:6
create table asset(
  id serial primary key,
  name text,
  assetid text,
  project_id int references project(id));

--changeset siewer:7
alter table asset add column origin text;

--changeset siewer:8
alter table asset add column active boolean;

--changeset siewer:9
create table interface (
  id serial primary key,
  privateip text,
  floatingip text,
  subnetid text,
  macaddr text,
  active boolean,
  asset_id int references asset(id));

--changeset siewer:10
alter table iaasapi add column token text;
alter table iaasapi add column tokenexpires text;

--changeset siewer:11
alter table iaasapi add column enabled boolean;

--changeset siewer:12
create table securitygroup(
  id serial primary key,
  name text,
  securitygroupid text);

create table securitygrouprule(
  id serial primary key,
  securitygroup_id int references securitygroup(id),
  direction text,
  type text,
  protocol text,
  ports text,
  destination text);

create table asset_securitygroup(
  asset_id int references asset(id),
  securitygroup_id int references securitygroup(id));

--changeset siewer:13
alter table securitygrouprule add column ruleid text;

--changeset siewer:14
alter table project add column ciid text;

--changeset siewer:15
alter table iaasapi add column status boolean;
update iaasapi set status = false;

--changeset siewer:16
create table proxies (
  id serial primary key,
  ip text,
  port text,
  description text);
alter table iaasapi add column external boolean;
update iaasapi set external=true;
insert into proxies (ip,port,description) values ('126.204.4.20','3128','BST lab proxy');

--changeset siewer:17
create table apitype(
  id serial primary key,
  url text,
  name text,
  description text);
create table apipermision(
  id serial primary key,
  cn text,
  ip text,
  project_id int references project(id));

insert into apitype (url, name , description) values ('cis-k8s','CIS k8s Benchmark','curl -k https://<stsc_url>/api/costam -X POST --cert <client_certificate> --key <client_private_key> -F file=@<file>');

--changeset siewer:18
alter table apipermision add column apitype_id int references apitype(id);

--changeset siewer:19
alter table apipermision add column enabled boolean;

--changeset siewer:20
create table node(
  id serial primary key,
  name text,
  type text,
  project_id int references project(id));
create table requirement(
  id serial primary key,
  code text unique,
  name text,
  severity int);
create table nodeaudit(
  id serial primary key,
  node_id int references node(id),
  requirement_id int references requirement(id),
  score text,
  updated text);

--changeset siewer:21
create table activity(
  id serial primary key,
  name text,
  inserted text);

--changeset siewer:22
alter table proxies add column username text;
alter table proxies add column password text;
create table nessus (
  id serial primary key,
  accesskey text,
  secretkey text,
  apiurl text,
  network text,
  status boolean,
  proxies_id int references proxies(id));
insert into proxies (ip,port,description) values ('126.204.4.20','3128','labproxy');

--changeset siewer:23
delete from proxies where description='labproxy';

--changeset siewer:24
create table nessusscantemplate(
  id serial primary key,
  name text,
  uuid text,
  nessus_id int references nessus(id));

create table nessusscanner(
  id serial primary key,
  expiration text,
  version text,
  scannerid int,
  nessus_id int references nessus(id));
update nessus set status = false;

--changeset siewer:25
alter table interface add column networktag text;
update interface set networktag = 'fe' where subnetid is not null;

--changeset siewer:26
create table nessusscan(
  id serial primary key,
  project_id int references project(id),
  nessusscanner_id int references nessusscanner(id),
  nessusscantemplate_id int references nessusscantemplate(id),
  nessus_id int references nessus(id),
  scanid int,
  running boolean,
  scheduled boolean,
  lastexecuted text,
  publicip boolean);

create table nessus_interface (
  nessusscan_id int references nessusscan(id),
  interface_id int references interface(id));

--changeset siewer:27
create table users (
  id serial primary key,
  commonname text unique,
  permisions text,
  lastloggeddate text,
  lastloggedip text);

--changeset siewer:28
alter table users add column enabled boolean;

--changeset siewer:29
alter table nessus add column usepublic boolean;

--changeset siewer:30
alter table nessusscan add column isautomatic boolean;

--changeset siewer:31
alter table nessusscan add column scanfrequency int;

--changeset siewer:32
alter table nessus add folderid int;

--changeset siewer:33
alter table nessus add username text;
alter table nessus add password text;
alter table nessus add configid text;
alter table nessusscan add targetid text;
alter table nessusscan add reportid text;
alter table nessusscan add taskid text;

--changeset siewer:34
create table infrastructurevuln(
  id serial primary key,
  interface_id int references interface(id),
  name text,
  threat text,
  port text,
  description text);

--changeset siewer:35
create table software(
  id serial primary key,
  name text,
  version text,
  asset_id int references asset(id));

--changeset siewer:36
create table codegroup(
  id serial primary key,
  project_id int references project(id),
  name text,
  basepath text,
  giturl text);
create table codeproject(
  id serial primary key,
  codegroup_id int references codegroup(id),
  name text);
create table codevuln(
  id serial primary key,
  codeproject_id int references codeproject(id),
  name text,
  filepath text,
  severity text,
  analysis text);
create table apis(
  url text,
  name text);

insert into apis (name, url) values ('FORTIFY_API','https://localhost:8445/');

--changeset siewer:37
alter table codegroup add column hasproject boolean;

--changeset siewer:38
alter table codevuln add column codegroup_id int references codegroup(id);

--changeset siewer:39
create table vulnhistory(
  id serial primary key,
  name text,
  vulnnumber int,
  inserted text);

--changeset siewer:40
alter table vulnhistory add column project_id int references project(id);

--changeset siewer:41
create table routingdomain(
  id serial primary key,
	name text
);
alter table iaasapi add column routingdomain_id int references routingdomain(id);
alter table interface add column routingdomain_id int references routingdomain(id);
alter table asset add column routingdomain_id int references routingdomain(id);
insert into routingdomain (name) values ('FE'), ('OpenWatt'), ('SK');

--changeset siewer:42
alter table nessus add column routingdomain_id int references routingdomain(id);

--changeset siewer:43
create table scannertype(
  id serial primary key,
	name text
);
alter table nessus add column scannertype_id int references scannertype(id);
insert into scannertype (name) values ('OpenVAS');
update nessus set scannertype_id=1;

--changeset siewer:44
insert into scannertype (name) values ('Nessus');

--changeset siewer:45
insert into scannertype (name) values ('Acunetix');

create table acunetix(
  id serial primary key,
  url text,
  apikey text,
  proxies_id int references proxies(id),
  profile text);

create table loginsequence(
  id serial primary key,
  loginsequencetext text);

create table webapp(
  id serial primary key,
  project_id int references project(id),
  url text,
  loginsequence_id int references loginsequence(id),
  lastexecuted text,
  target_id text,
  publicscan boolean);

create table webappscan(
  id serial primary key,
  acunetix_id int references acunetix(id),
  running boolean,
  scan_id text,
  type text,
  webapp_id int references webapp(id));

create table webappvuln(
  id serial primary key,
  webappscan_id int references webappscan(id),
  webapp_id int references webapp(id),
  name text,
  description text,
  location text,
  recommendation text);

--changeset siewer:46
alter table acunetix add column routingdomain_id int references routingdomain(id);

--changeset siewer:47
alter table acunetix add column scannertype_id int references scannertype(id);

--changeset siewer:48
alter table nessus add column apikey text;
alter table webappscan add column nessus_id int references nessus(id);

--changeset siewer:49
alter table loginsequence add column name text;

--changeset siewer:50
alter table webapp add column loginsequenceuploadurl text;

--changeset siewer:51
alter table webapp add column readytoscan boolean;

--changeset siewer:52
alter table webapp add column running boolean;

--changeset siewer:53
alter table webapp add column scanid text;

--changeset siewer:54
alter table webappscan add column project_id int references project(id);

--changeset siewer:55
create table webappheader(
  id serial primary key,
	headername text,
	headervalue text,
	webapp_id int references webapp(id));

--changeset siewer:56
alter table webappvuln add column severity text;

--changeset siewer:57
insert into apitype (url, name, description) values ('webapp', 'WebApps Service Discovery', '');

--changeset siewer:58
alter table webapp add column asset_id int references asset(id);

--changeset siewer:59
alter table webapp add column inqueue boolean;

--changeset siewer:60
update webapp set inqueue=false;

--changeset siewer:61
create table softwarepacket(
  id serial primary key,
	name text);
create table asset_softwarepacket(
  asset_id int references asset(id),
  softwarepacket_id int references softwarepacket(id));

--changeset siewer:62
alter table asset add os text;
alter table asset add osversion text;
alter table asset add fix text;

--changeset siewer:63
alter table softwarepacket add uptated boolean;

--changeset siewer:64
create table softwarepacketvulnerability (
  id serial primary key,
  name text,
  softwarepacket_id int references softwarepacket(id),
  score text);

--changeset siewer:65
alter table webapp add lastscan text;

--changeset siewer:66
alter table softwarepacketvulnerability add column fix text;

--changeset siewer:67
alter table webapp add column inserted text;

--changeset siewer:68
alter table infrastructurevuln add column inserted text;
alter table codevuln add column inserted text;
alter table softwarepacketvulnerability add column inserted text;

--changeset siewer:69
insert into scannertype (name) values ('Fortify SSC');

--changeset siewer:70
alter table nessus add column fortifytoken text;
alter table nessus add column fortifytokenexpiration text;

--changeset siewer:80
alter table codegroup add column versionid integer;

--changeset siewer:81
alter table codevuln add column description text;

--changeset siewer:82
alter table interface add column hostid integer;

--changeset siewer:83
alter table nodeaudit add column apitype_id int references apitype(id);
update nodeaudit set apitype_id=1;
insert into apitype (url,name) values ('cis-docker', 'CIS Docker Benchark');

--changeset siewer:8445/
alter table softwarepacketvulnerability add column project_id int references project(id);

--changeset siewer:84
alter table webapp add column codegroup_id int references codegroup(id);
alter table webapp add column codeproject_id int references codeproject(id);

--changeset siewer:85
alter table vulnhistory add column codevulnnumber int;
alter table vulnhistory add column webappvulnnumber int;
alter table vulnhistory add column auditvulnnumber int;
alter table vulnhistory rename vulnnumber to infrastructurevulnnumber;

--changeset siewer:86
truncate table vulnhistory;

--changeset siewer:87
insert into apitype (url,name,description) values ('sast','Statyczne analizy kodu źródłowego - zlecanie','Statyczne analizy kodu źródłowego - zlecanie');

--changeset siewer:88
create table codescan(
  id serial primary key,
  inQueue boolean,
  codegroup_id int references codegroup(id),
  inserted text,
  running boolean,
  codeproject_id int references codeproject(id)
);

--changeset siewer:89
alter table project add column contactlist text;

--changeset siewer:90
alter table asset add column assettype text;
update asset set assettype='SINGLE';

--changeset siewer:91
alter table interface add column pool text;
alter table interface add column autocreated boolean;
update interface set autocreated=false;
--changeset siewer:92
insert into scannertype (name) values ('Nexpose');
--changeset siewer:93
alter table nessus add column engineId int;
alter table nessus add column template text;

--changeset siewer:94
create table journal (
  id serial primary key,
  name text,
  inserted timestamp not null default now(),
  users_id int references users(id),
  project_id int references project(id)
);

--changeset siewer:95
alter table journal add column cnname text;

--changeset siewer:96
alter table journal alter column inserted drop not null;

--changeset siewer:97
alter table project add column webappautodiscover boolean;

--changeset siewer:98
alter table webapp add column autostart boolean;

--changeset siewer:99
alter table webappvuln add column codeproject_id int references codeproject(id);

--changeset siewer:100
create table cioperations(
  id serial primary key,
  project_id int references project(id),
  codeproject_id int references codeproject(id),
  codegroup_id int references codegroup(id),
  inserted timestamp default now(),
  vulnnumber int,
  result text
);

--changeset siewer:101
alter table codegroup add column repourl text;
alter table codegroup add column repousername text;
alter table codegroup add column repopassword text;
alter table codegroup add column running boolean;
alter table codegroup add column jobid text;
alter table codegroup add column inqueue boolean;
alter table codegroup add column auto boolean;
alter table codeproject add column repourl text;
alter table codeproject add column repousername text;
alter table codeproject add column repopassword text;

--changeset siewer:102
alter table codeproject add column technique text;
alter table codegroup add column technique text;
insert into scannertype (name) values ('Fortify SCA Rest API');

--changeset siewer:103
alter table codegroup add column versionidall int;
alter table codegroup add column versionidsingle int;
update codegroup set versionidall=versionid;
alter table codegroup drop column versionid;

--changeset siewer:104
update codegroup set versionidsingle=0;
--changeset siewer:105
alter table codegroup add column requestid text;
alter table codegroup add column scanid text;

--changeset siewer:106
alter table codegroup add column scope text;

--changeset siewer:107
alter table codeproject add column skipallscan boolean;
update codeproject set skipallscan=false;

--changeset siewer:108
alter table codeproject add column additionalpath text;

--changeset siewer:109
create table webappcookies(
    id serial primary key,
    webapp_id int references webapp(id),
    cookie text,
    url text
);
--changeset siewer:110
alter table codeproject add column inqueue boolean;
update codeproject set inqueue=false;
--changeset siewer:111
create table fortifysingleapp(
    id serial primary key,
    requestid text,
    codeproject_id int references codeproject(id),
    codegroup_id int references codegroup(id),
    jobtoken text,
    finished boolean,
    downloaded boolean
);
--changeset siewer:112
alter table nessus add column rfwscannerip text;

--changeset siewer:113
create table status(
    id serial primary key,
    name text
);
insert into status (name) values ('NEW'),('EXISTING');
create table service(
    id serial primary key,
    port int,
    name text,
    netproto text,
    appproto text,
    interface_id int references interface(id),
    status_id int references status(id)
);
alter table infrastructurevuln add column status_id int references status(id);

--changeset siewer:114
alter table nessusscan add column requestid text;
alter table asset add column requestid text;

--changeset siewer:115
alter table interface add column scanrunning boolean;
alter table project add column autowebappscan boolean;
update interface set scanrunning=false;
update project set autowebappscan=false;

--changeset siewer:116
alter table project add column autocodescan boolean;
update project set autocodescan = false;

--changeset siewer:117
alter table asset_securitygroup drop constraint "asset_securitygroup_asset_id_fkey", add constraint "asset_securitygroup_asset_id_fkey" foreign key ("asset_id") references "asset"(id) on delete cascade;

--changeset siewer:118
alter table project add column apikey text;

--changeset siewer:119
alter table users add column username text;
alter table users add column password text;

--changeset siewer:120
alter table users add column logins int;
alter table users add column failedlogins int;
update users set logins = 0;
update users set failedlogins = 0;

--changeset siewer:121
alter table codeproject add column commitid text;

--changeset siewer:122
alter table interface drop constraint interface_asset_id_fkey, add constraint interface_asset_id_fkey foreign key ("asset_id") references "asset"(id) on delete cascade;

--changeset siewer:123
alter table vulnhistory drop constraint vulnhistory_project_id_fkey, add constraint vulnhistory_project_id_fkey foreign key ("project_id") references "project"(id) on delete cascade;

--changeset siewer:124
alter table webappvuln drop constraint "webappvuln_webapp_id_fkey", add constraint "webappvuln_webapp_id_fkey" foreign key ("webapp_id") references "webapp"(id) on delete cascade;
alter table webappheader drop constraint "webappheader_webapp_id_fkey", add constraint "webappheader_webapp_id_fkey" foreign key ("webapp_id") references "webapp"(id) on delete cascade;
alter table webappcookies drop constraint "webappcookies_webapp_id_fkey", add constraint "webappcookies_webapp_id_fkey" foreign key ("webapp_id") references "webapp"(id) on delete cascade;

--changeset siewer:125
create table settings (
    id serial primary key,
    initialized boolean
);
insert into settings (initialized) values (false);

--changeset siewer:126
alter table codeproject add column running boolean;
update codeproject set running=false;

--changeset siewer:127
insert into apitype (url, name , description) values ('mvndependencycheck','Download for MVN Dependency Check by owasp','');

--changeset siewer:128
create table codeproject_softwarepacket(
    codeproject_id int references codeproject(id),
    softwarepacket_id int references softwarepacket(id));
alter table softwarepacketvulnerability add column description text;
alter table softwarepacketvulnerability add column severity text;

--changeset siewer:129
alter table vulnhistory add column softwarepacketvulnnumber int;
update vulnhistory set  softwarepacketvulnnumber=0;

--changeset siewer:130
alter table project add column autoinfrascan boolean;
update project set autoinfrascan= false;
