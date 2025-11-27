package keycloak.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import keycloak.enums.ETokenType;
import keycloak.exception.CustomException;
import keycloak.payload.IntrospectResponse;
import keycloak.payload.KeycloakTokenResponse;
import keycloak.payload.LoginRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {
    @Value("${spring.jwt.jwtSecretKey}")
    private String accessSecretKey;

    @Value("${spring.keycloak.realm-url}")
    private String authServerUrl;

    @Value("${spring.keycloak.realm-name}")
    private String realm;

    @Value("${spring.keycloak.client-id}")
    private String clientId;

    @Value("${spring.keycloak.client-secret}")
    private String clientSecret;

    private final RestTemplate restTemplate = new RestTemplate();

    public KeycloakTokenResponse getTokenKeycloak(LoginRequest loginRequest) {
        String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", authServerUrl, realm);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("username", loginRequest.getUsername());
        body.add("password", loginRequest.getPassword());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, new ParameterizedTypeReference<>() {
            });

            if (response.getStatusCode() != HttpStatus.OK) {
                throw new CustomException("Failed to authenticate with Keycloak");
            }

            Map<String, Object> responseBody = response.getBody();

            if (responseBody == null) {
                throw new CustomException("Empty response from Keycloak");
            }
            return KeycloakTokenResponse.builder().accessToken(String.valueOf(responseBody.get("access_token"))).refreshToken(String.valueOf(responseBody.get("refresh_token"))).build();
        } catch (Exception e) {
            throw new CustomException("Failed to get token from Keycloak: " + e.getMessage(), e);
        }
    }

    public boolean introspectKeyCloakToken(String token) {
        try {
            String introspectUrl = String.format(
                    "%s/realms/%s/protocol/openid-connect/token/introspect",
                    authServerUrl,
                    realm
            );

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("token", token);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(introspectUrl, HttpMethod.POST, request, new ParameterizedTypeReference<>() {
            });

            if (response.getStatusCode() != HttpStatus.OK) {
                return false;
            }

            Map<String, Object> responseBody = response.getBody();
            if (responseBody == null) {
                return false;
            }

            return Boolean.TRUE.equals(responseBody.get("active"));

        } catch (Exception e) {
            throw new CustomException("Failed to introspect token: " + e.getMessage(), e);
        }
    }

    private IntrospectResponse introspectToken(String token){
        try {
            String introspectUrl = String.format(
                    "%s/realms/%s/protocol/openid-connect/token/introspect",
                    authServerUrl,
                    realm
            );

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setBasicAuth(clientId,clientSecret);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("token", token);
            body.add("token_type_hint", "access_token");
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            ResponseEntity<IntrospectResponse> response = restTemplate.exchange(introspectUrl, HttpMethod.POST, request,  IntrospectResponse.class);

            return response.getBody();
        }catch (Exception e){
            throw new CustomException("Error", e);
        }
    }

    private SecretKey accessSecretKey(){
        byte[] keyBytes = Decoders.BASE64.decode(accessSecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateInternalAccessToken(IntrospectResponse introspectResponse) {
        try {
            Map<String, Object> customClaims = new HashMap<>();
            customClaims.put("FullName", introspectResponse.getName());
            customClaims.put("Email", introspectResponse.getEmail());
            customClaims.put("TokenType", ETokenType.INTERNAL_ACCESS_TOKEN.toString());
            customClaims.put("RealmsRoles", introspectResponse.getRealmRoles());
            customClaims.put("ClientRoles", introspectResponse.getResourceRoles());

            if (introspectResponse.getGivenName() != null) {
                customClaims.put("GivenName", introspectResponse.getGivenName());
            }
            if (introspectResponse.getFamilyName() != null) {
                customClaims.put("FamilyName", introspectResponse.getFamilyName());
            }
            return Jwts.builder()
                    .issuer("KeyCloak + Jwt")
                    .subject(introspectResponse.getPreferredUsername())
                    .claims(customClaims)
                    .issuedAt(new Date())
                    .expiration(new Date(Instant.now().plus(3600000,ChronoUnit.SECONDS).toEpochMilli()))
                    .signWith(accessSecretKey())
                    .compact();
        } catch (Exception e) {
            throw new CustomException("Error");
        }
    }

    public String generateInternalTokenFromKeycloak(String token){
        IntrospectResponse introspectResponse = introspectToken(token);

        if (!introspectResponse.isActive()) {
            throw new CustomException("Keycloak token is not active or invalid");
        }

        return generateInternalAccessToken(introspectResponse);
    }

    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().verifyWith(accessSecretKey()).build().parseSignedClaims(token).getPayload();
    }

    public List<String> getRealmRolesFromInternalToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        Object roleClaim = claims.get("RealmsRoles");
        if (roleClaim instanceof List<?>) {
            return ((List<?>) roleClaim).stream().filter(String.class::isInstance).map(Object::toString).toList();
        }
        return List.of();
    }

    public Map<String, List<String>> getClientRolesFromInternalToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        Object clientRoles = claims.get("ClientRoles");
        if (clientRoles instanceof Map<?, ?> clientMap) {
            Map<String, List<String>> result = new HashMap<>();
            for (Map.Entry<?, ?> entry : clientMap.entrySet()) {
                if (entry.getKey() instanceof String key && entry.getValue() instanceof List<?> list) {
                    result.put(key, list.stream().map(Object::toString).toList());
                }
            }
            return result;
        }
        return Map.of();
    }

    public boolean validateInternalToken(String authToken) {
        try {
            Jwts.parser().verifyWith(accessSecretKey()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    public String getUsernameFromToken(String token) {
        return getAllClaimsFromToken(token).getSubject();
    }

}
