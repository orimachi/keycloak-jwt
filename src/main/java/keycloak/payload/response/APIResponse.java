package keycloak.payload.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "API response")
public class APIResponse<T> {
    @Builder.Default
    int status = 200;

    String message;

    T result;
}
