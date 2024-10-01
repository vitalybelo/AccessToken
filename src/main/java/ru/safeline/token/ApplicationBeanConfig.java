package ru.safeline.token;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class ApplicationBeanConfig {


    @Value("${mo.eca.keycloak.admin.client_id}")
    private String clientName;
    @Value("${mo.eca.keycloak.admin.client_secret}")
    private String clientSecret;
    @Value("${mo.eca.keycloak.server.url}")
    private String serverURL;
    @Value("${mo.eca.keycloak.realm}")
    private String realmName;


    @Bean
    Keycloak keycloak() {
        return KeycloakBuilder.builder()
                .serverUrl(serverURL)
                .realm(realmName)
                .clientId(clientName)
                .clientSecret(clientSecret)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build();
    }

    @Bean
    public RealmResource realmResource() {
        return KeycloakBuilder.builder()
                .serverUrl(serverURL)
                .realm(realmName)
                .clientId(clientName)
                .clientSecret(clientSecret)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build().realm(realmName);
    }

}
