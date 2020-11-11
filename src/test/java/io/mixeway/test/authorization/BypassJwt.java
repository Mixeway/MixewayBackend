package io.mixeway.test.authorization;


import io.mixeway.rest.utils.JwtUserDetailsService;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.MockReset;

import java.lang.annotation.*;

@Documented
@Inherited
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@MockBean(value = JwtUserDetailsService.class, reset = MockReset.NONE)
public @interface BypassJwt {

}
