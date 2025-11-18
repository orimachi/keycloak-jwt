package keycloak;

import keycloak.utils.DotEnv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class KeycloakApplication {

	public static void main(String[] args) {
		DotEnv.load();
		SpringApplication.run(KeycloakApplication.class, args);
	}

}
