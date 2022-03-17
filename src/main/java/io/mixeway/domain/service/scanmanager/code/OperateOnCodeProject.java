package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeProject;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class OperateOnCodeProject {



    /**
     * Method which verify if CodeProject scan can be started
     * @param cp CodeProject to be verified
     * @return true if scan can be run, false if not
     */
    public boolean canScanCodeProject(CodeProject cp) {
        if (cp.getRunning())
            return false;
        else if (cp.getCodeGroup().getProjects().stream().anyMatch(CodeProject::getRunning))
            return false;
        else return !cp.getCodeGroup().isRunning();
    }
}
