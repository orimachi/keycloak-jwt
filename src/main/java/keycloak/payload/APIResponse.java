package keycloak.payload;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class APIResponse<T> {
    @Builder.Default
    int status = 200;

    String message;

    T result;
}
