package io.mixeway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import springfox.documentation.builders.ParameterBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.schema.ModelRef;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.service.Parameter;
import springfox.documentation.service.VendorExtension;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.*;

@Configuration
@EnableSwagger2
@EnableWebMvc
public class SwaggerConfig implements WebMvcConfigurer {
    private Contact contact = new Contact(
            "Info at",
            "https://github.com/Mixeway/MixeWayBackend",
            "gsiewruk@gmail.com"
    );




    private List<VendorExtension> vendorExtensions = new ArrayList<>();
    private ApiInfo apiInfo = new ApiInfo(
            "Mixeway REST API",
            "Prefix prefix /api/ is deprecated please migrate to /v2/", "1.0",
            "#", contact,
            "Apache 2.0", "http://www.apache.org/licenses/LICENSE-2.0",vendorExtensions);
    @Bean
    public Docket api() {

        Parameter headerParam = new ParameterBuilder()
                .name("apiKey").defaultValue("").parameterType("header")
                .modelRef(new ModelRef("string")).description("ApiKey").required(true).build();

        return new Docket(DocumentationType.SWAGGER_2).select()
                .apis(RequestHandlerSelectors.any())
                .paths(PathSelectors.any())
                .build()
                .apiInfo(apiInfo)
                .globalOperationParameters(Collections.singletonList(headerParam));
    }
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        System.out.println("loading registry...");
        registry.addResourceHandler("swagger-ui.html")
                .addResourceLocations("classpath:/META-INF/resources/");

        registry.addResourceHandler("/webjars/**")
                .addResourceLocations("classpath:/META-INF/resources/webjars/");
    }
}