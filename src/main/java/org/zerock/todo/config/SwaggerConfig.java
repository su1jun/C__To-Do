package org.zerock.todo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RestController;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.ApiKey;
import springfox.documentation.service.AuthorizationScope;
import springfox.documentation.service.SecurityReference;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;

import java.util.List;
@Configuration // openapi 문서화 클래스 사용
public class SwaggerConfig {
    @Bean
    public Docket api() {
        return new Docket(DocumentationType.OAS_30)
                .useDefaultResponseMessages(false)
                .select()
                .apis(RequestHandlerSelectors.withClassAnnotation(RestController.class))
                .paths(PathSelectors.any())
                .build()
                .securitySchemes(List.of(apiKey())) //추가된 부분
                .securityContexts(List.of(securityContext())) //추가된 부분
                .apiInfo(apiInfo());
    }

    private ApiInfo apiInfo() { // api 문서 설정
        return new ApiInfoBuilder()
                .title("Boot API 01 Project Swagger")
                .build();
    }

    private ApiKey apiKey() { // 보안 인증 키 정의
        return new ApiKey("Authorization", "Bearer Token", "header");
    }
    private SecurityContext securityContext() { // 보안 url 지정
        return SecurityContext.builder().securityReferences(defaultAuth())
                .operationSelector(selector -> selector.requestMappingPattern().startsWith("/todo/")).build();
    }
    
    private List<SecurityReference> defaultAuth() { // 보안키 참고
        AuthorizationScope authorizationScope = new AuthorizationScope("global", "global access");
        return List.of(new SecurityReference("Authorization", new AuthorizationScope[] {authorizationScope}));
    }
}
