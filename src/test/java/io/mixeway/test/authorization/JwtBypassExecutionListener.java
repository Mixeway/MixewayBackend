package io.mixeway.test.authorization;

import io.mixeway.config.Constants;
import io.mixeway.rest.utils.JwtUserDetailsService;
import org.jetbrains.annotations.NotNull;
import org.junit.platform.commons.util.AnnotationUtils;
import org.mockito.Mockito;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.support.AbstractTestExecutionListener;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;

public class JwtBypassExecutionListener extends AbstractTestExecutionListener {

    @Override
    public void beforeTestMethod(TestContext testContext) throws Exception {
        Optional<BypassJwt> annotation = AnnotationUtils.findAnnotation(testContext.getTestClass(), BypassJwt.class);
        annotation.ifPresent(mock -> mockJWTAuthorization(testContext));
        super.beforeTestMethod(testContext);
    }

    private void mockJWTAuthorization(TestContext context) {
        JwtUserDetailsService jwtUserDetailsService = context.getApplicationContext().getBean(JwtUserDetailsService.class);
        Mockito.when(jwtUserDetailsService.loadUserByApiKeyAndRequestUri(any(),any())).thenReturn(getAdminUser());
        Mockito.when(jwtUserDetailsService.loadUserByUsername(any())).thenReturn(getAdminUser());
    }

    @NotNull
    private User getAdminUser() {
        return new User("admin", "", AuthorityUtils.commaSeparatedStringToAuthorityList(
                "," + Constants.ROLE_USER
                        + "," +Constants.ROLE_EDITOR_RUNNER
                        + "," +Constants.ROLE_API
                        + "," +Constants.ROLE_AUDITOR
                        + "," +Constants.ROLE_ADMIN  ));
    }
}
