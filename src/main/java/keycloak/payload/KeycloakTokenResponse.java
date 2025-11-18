package keycloak.payload;

import lombok.*;

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class KeycloakTokenResponse {
    String accessToken;

    String refreshToken;
}
