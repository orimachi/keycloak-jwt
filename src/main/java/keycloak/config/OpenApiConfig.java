package keycloak.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {
    private final String securitySchemeName = "bearerAuth";

    @Value("${spring-docs.title}")
    private String title;

    @Value("${spring-docs.version}")
    private String version;

    @Value("${spring-docs.description-info}")
    private String descriptionInfo;

    @Value("${spring-docs.server-url}")
    private String serverUrl;

    @Value("${spring-docs.description-server}")
    private String descriptionServer;

    @Bean
    public OpenAPI openAPI(@Value("title") String title){
        return new OpenAPI()
                .info(new Info()
                        .title(title)
                        .version(version)
                        .description(descriptionInfo)
                        .contact(new Contact().name("orimachi"))
                )
                .servers(List.of(new Server().url(serverUrl).description(descriptionServer)))
                .components(new Components().addSecuritySchemes(securitySchemeName,new SecurityScheme().name("Authorization")
                        .type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")))
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName));
    }

    @Bean
    public GroupedOpenApi groupedOpenApi(){
        return GroupedOpenApi.builder()
                .group("SERVICE")
                .packagesToScan("keycloak.controller")
                .build();
    }
}
