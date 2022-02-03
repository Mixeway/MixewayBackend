/*
 * @created  2021-01-26 : 12:17
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.integrations;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mixeway.db.entity.CisRequirement;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.integrations.codescan.plugin.checkmarx.model.CxSetGitRepo;
import liquibase.pro.packaged.C;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.util.EntityUtils;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@RunWith(SpringRunner.class)
public class Test {

    @org.junit.Test
    public void testvoid() throws IOException {
        CodeProject cp = new CodeProject();
        cp.setRepoUrl("http://test");
        HttpEntity<CxSetGitRepo> cxSetGitRepoHttpEntity = new HttpEntity<>(new CxSetGitRepo(cp, "test:dsa"), new HttpHeaders());
        ObjectMapper mapper = new ObjectMapper();
        String jsonStr = mapper.writeValueAsString(cxSetGitRepoHttpEntity);

        System.out.println(jsonStr);

    }
}
