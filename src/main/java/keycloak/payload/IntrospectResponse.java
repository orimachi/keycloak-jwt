package keycloak.payload;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class IntrospectResponse {
    private boolean active;

    private String sub;

    private String iss;

    @JsonProperty("preferred_username")
    private String preferredUsername;

    private String email;

    @JsonProperty("email_verified")
    private boolean emailVerified;

    private String name;

    @JsonProperty("given_name")
    private String givenName;

    @JsonProperty("family_name")
    private String familyName;

    private Long exp;
    private Long iat;
    private String jti;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("username")
    private String username;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("realm_access")
    private void unpackRealmAccess(Map<String, Object> realmAccess) {
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            this.realmRoles = (List<String>) realmAccess.get("roles");
        }
    }

    @Builder.Default
    private List<String> realmRoles = new ArrayList<>();

    @JsonProperty("resource_access")
    private void unpackResourceAccess(Map<String, Object> resourceAccess) {
        if (resourceAccess != null) {
            Map<String, List<String>> roles = new HashMap<>();
            resourceAccess.forEach((key, value) -> {
                if (value instanceof Map) {
                    Map<String, Object> clientData = (Map<String, Object>) value;
                    if (clientData.containsKey("roles")) {
                        roles.put(key, (List<String>) clientData.get("roles"));
                    }
                }
            });
            this.resourceRoles = roles;
        }
    }

    @Builder.Default
    private Map<String, List<String>> resourceRoles = new HashMap<>();
}
