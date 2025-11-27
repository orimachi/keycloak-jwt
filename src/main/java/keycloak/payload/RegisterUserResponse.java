package keycloak.payload;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

import java.util.List;

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Register User Response")
public class RegisterUserResponse {
    @Schema(name = "id", description = "return id user", example = "1")
    String id;

    @Schema(name = "username", description = "return username user", example = "John Doe")
    String username;

    @Schema(name = "email", description = "return email user", example = "john@gmail.com")
    String email;

    @Schema(name = "roles", description = "return roles user", example = "USER")
    List<String> roles;
}
