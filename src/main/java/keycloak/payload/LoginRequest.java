package keycloak.payload;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
@Getter
@Setter
public class LoginRequest {
    String username;

    String password;
}
