package keycloak.utils;

import io.github.cdimascio.dotenv.Dotenv;

public class DotEnv {

    private DotEnv(){
        throw new IllegalStateException("Utils class");
    }

    public static void load(){
        Dotenv.load().entries().forEach(entry -> System.setProperty(entry.getKey(),entry.getValue()));
    }
}
