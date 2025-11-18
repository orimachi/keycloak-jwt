package keycloak.config;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakConfig {
    @Value("${spring.keycloak.realm-name}")
    private String realmName;

    @Value("${spring.keycloak.realm-url}")
    private String realmUrl;

    @Value("${spring.keycloak.client-id}")
    private String clientId;

    @Value("${spring.keycloak.client-secret}")
    private String clientSecret;

    @Bean
    public Keycloak keycloak(){
        return KeycloakBuilder.builder()
                .realm(realmName)
                .serverUrl(realmUrl)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build();
    }
}
