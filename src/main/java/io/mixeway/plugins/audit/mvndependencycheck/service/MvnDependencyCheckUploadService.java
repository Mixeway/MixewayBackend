package io.mixeway.plugins.audit.mvndependencycheck.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.SoftwarePacket;
import io.mixeway.db.entity.SoftwarePacketVulnerability;
import io.mixeway.db.repository.*;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.Status;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import sun.rmi.runtime.Log;

import java.io.File;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Optional;

@Service
public class MvnDependencyCheckUploadService {
    private DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final Logger log = LoggerFactory.getLogger(MvnDependencyCheckUploadService.class);
    private final CodeGroupRepository codeGroupRepository;
    private final ProjectRepository projectRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final SoftwarePacketRepository softwarePacketRepository;
    private final SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;
    private final StatusRepository statusRepository;
    @Autowired
    MvnDependencyCheckUploadService(CodeGroupRepository codeGroupRepository, ProjectRepository projectRepository,
                                    CodeProjectRepository codeProjectRepository, SoftwarePacketRepository softwarePacketRepository,
                                    SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository, StatusRepository statusRepository){
        this.codeGroupRepository = codeGroupRepository;
        this.codeProjectRepository =  codeProjectRepository;
        this.projectRepository = projectRepository;
        this.softwarePacketRepository = softwarePacketRepository;
        this.softwarePacketVulnerabilityRepository = softwarePacketVulnerabilityRepository;
        this.statusRepository = statusRepository;
    }


    public ResponseEntity<Status> mvnDependencyCheck(String codeGroup, String codeProject, Long id, MultipartFile file) throws IOException {
        Optional<CodeGroup> cg = codeGroupRepository.findByProjectAndName(projectRepository.getOne(id), codeGroup);
        if (cg.isPresent()){
            Optional<CodeProject> cp = codeProjectRepository.findByCodeGroupAndName(cg.get(),codeProject);
            if (cp.isPresent()){
                loadSoftwarePackets(cp.get(),file);
            } else {
                CodeProject codeProject1 = new CodeProject();
                codeProject1.setCodeGroup(cg.get());
                codeProject1.setName(codeProject);
                codeProject1.setSkipAllScan(true);
                codeProjectRepository.save(codeProject1);
                log.info("Created new CodeProject {} for group {} of {}", LogUtil.prepare(codeProject),LogUtil.prepare(codeGroup),cg.get().getProject().getName());
                loadSoftwarePackets(codeProject1,file);
            }
        }
        return new ResponseEntity<>(HttpStatus.OK);
    }
    private void loadSoftwarePackets(CodeProject codeProject, MultipartFile file) throws IOException {
        codeProject.getSoftwarePackets().removeAll(codeProject.getSoftwarePackets());
        Document doc = Jsoup.parse(multipartToFile(file), "UTF-8", "");
        Elements packagesWithVulns = doc.select("h3.subsectionheader.standardsubsection").not("h3.notvulnerable");
        SoftwarePacket softwarePacket;
        for (Element vulnHeader : packagesWithVulns){
            Optional<SoftwarePacket> softPacket = softwarePacketRepository.findByName(vulnHeader.text());
            if (softPacket.isPresent()) {
                codeProject.getSoftwarePackets().add(softPacket.get());
                softwarePacket = softPacket.get();
            }
            else {
                softwarePacket = new SoftwarePacket();
                softwarePacket.setName(vulnHeader.text());
                softwarePacketRepository.save(softwarePacket);
                codeProject.getSoftwarePackets().add(softwarePacket);
            }
            for (Element vulns : vulnHeader.nextElementSibling().select("h4:contains(Published Vulnerabilities)")){
                Element vulnCVE = vulns.nextElementSibling().select("p > b > a").first();
                if (vulnCVE == null){
                    vulnCVE = vulns.nextElementSibling().select("p > b").first();
                }
                Element vulnDescription = vulns.nextElementSibling().select("pre").first();
                Element cvsScore = vulns.nextElementSibling().select("ul>li:contains(Base Score)").get(1);
                this.saveVuln(vulnCVE.text(),cvsScore.text(),vulnDescription.text(),softwarePacket,codeProject);
            }
        }
    }
    private void saveVuln(String cve, String score, String description, SoftwarePacket softwarePacket, CodeProject codeProject){
        SoftwarePacketVulnerability spv;
        Optional<SoftwarePacketVulnerability> softwarePacketVulnerability = softwarePacketVulnerabilityRepository.findByName(cve);
        if (softwarePacketVulnerability.isPresent()){
            spv = softwarePacketVulnerability.get();
            spv.setStatus(statusRepository.findByName(Constants.STATUS_EXISTING));
        } else {
            spv = new SoftwarePacketVulnerability();
            spv.setStatus(statusRepository.findByName(Constants.STATUS_NEW));
        }
        spv.setName(cve);
        spv.setScore(Double.valueOf(score.split(" \\(")[1].substring(0, (score.split(" \\(")[1].length() - 1))));
        spv.setInserted(dateFormat.format(new Date()));
        spv.setSoftwarepacket(softwarePacket);
        spv.setProject(codeProject.getCodeGroup().getProject());
        spv.setDescription(description);
        softwarePacketVulnerabilityRepository.save(spv);

        log.info("Saved new vulnerability {} with score {} for CodeProject {} of {}", LogUtil.prepare(spv.getName()),
                spv.getScore(),LogUtil.prepare(codeProject.getName()),LogUtil.prepare(codeProject.getCodeGroup().getProject().getName()));

    }
    private  static File multipartToFile(MultipartFile multipart) throws IllegalStateException, IOException {
        File convFile = new File(System.getProperty("java.io.tmpdir")+"/owaspreport");
        multipart.transferTo(convFile);
        return convFile;
    }


}
