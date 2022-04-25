package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.scanmanager.model.SASTRequestVerify;
import io.mixeway.utils.LogUtil;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@AllArgsConstructor
@Log4j2
public class VerifySASTPermissionsService {
    private final CodeProjectRepository codeProjectRepository;

//    public SASTRequestVerify verifyIfCodeProjectExists(Optional<CodeProject> cp, String projectName, boolean depCheck){
//        SASTRequestVerify sastRequestVerify = new SASTRequestVerify();
//        Optional<CodeProject> codeProject = codeProjectRepository.find(cg.get(),projectName);
//        if (cp.isPresent() && (cp.get().getCodeGroup().getVersionIdsingle() > 0 || depCheck)){
//            sastRequestVerify.setValid(true);
//            sastRequestVerify.setCg(cg.get());
//            sastRequestVerify.setCp(cp.get());
//            return sastRequestVerify;
//        }
//        else{
//            sastRequestVerify.setValid(false);
//            sastRequestVerify.setCp(cg.get());
//            return sastRequestVerify;
//        }
//    }
//
//    public SASTRequestVerify verifyIfCodeGroupIsNotPresent(){
//        SASTRequestVerify sastRequestVerify = new SASTRequestVerify();
//        sastRequestVerify.setValid(false);
//        return sastRequestVerify;
//    }
//
//    public SASTRequestVerify returnNotValidRequestWithGroup(Optional<CodeProject> cg) {
//        SASTRequestVerify sastRequestVerify = new SASTRequestVerify();
//        sastRequestVerify.setValid(false);
//        sastRequestVerify.setCp(cg.get());
//        return sastRequestVerify;
//    }
//
//    public SASTRequestVerify returnNotValidRequestWithLog(String groupName, String logMsg) {
//        SASTRequestVerify sastRequestVerify = new SASTRequestVerify();
//        log.info("{} {}", LogUtil.prepare(groupName), LogUtil.prepare(logMsg));
//        sastRequestVerify.setValid(false);
//        return sastRequestVerify;
//    }
}
