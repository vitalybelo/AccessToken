package ru.safeline.token;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;

import java.security.Principal;

/**
 * Авторизационный класс для чтения данных из токена доступа аутентифицированного запроса
 *
 * @author Vitali Belotserkovskii, 14.09.2023
 */
@Slf4j
@Service
@SuppressWarnings("unused")
public class AuthorizationService {

    private final static String CLAIM_USER_ID = "sub";
    private final static String CLAIM_CLIENT_ID = "azp";
    private final static String CLAIM_USERNAME = "preferred_username";


    /**
     * Переопределяет экземпляр класса Principal в экземпляр класса токена доступа: JwtAuthenticationToken
     *
     * @param principal класс java.security поступающий на вход контроллера spring boot frameworks
     * @return экземпляр класса JwtAuthenticationToken или null
     */
    private JwtAuthenticationToken getJwtToken(Principal principal) {

        if (principal instanceof JwtAuthenticationToken) {
            return (JwtAuthenticationToken) principal;
        }
        return null;
    }


    /**
     * Переопределяет экземпляр класса Principal в экземпляр класса токена доступа: OidcUser
     *
     * @param principal класс java.security поступающий на вход контроллера spring boot frameworks
     * @return экземпляр класса OidcUser или null
     */
    private OidcUser getOidcUser(Principal principal) {

        if (principal instanceof Authentication) {
            Authentication authentication = (Authentication) principal; // не убирать
            if (authentication.getPrincipal() instanceof OidcUser) {
                return (OidcUser) authentication.getPrincipal();
            }
        }
        return null;
    }


    /**
     * Читает из claim утверждений токена доступа идентификатор пользователя
     *
     * @param principal класс java.security поступающий на вход контроллера
     * @return id пользователя keycloak, или null
     */
    public String getUserId(Principal principal) {

        OidcUser oidcUser = getOidcUser(principal);
        if (oidcUser != null) {
            return oidcUser.getClaimAsString(CLAIM_USER_ID);
        }
        JwtAuthenticationToken jwtToken = getJwtToken(principal);
        if (jwtToken != null) {
            Object object = jwtToken.getTokenAttributes().get(CLAIM_USER_ID);
            return object != null ? (String) object : null;
        }
        return null;
    }


    public String getUserId(OidcUser oidcUser) {

        if (oidcUser != null) {
            return oidcUser.getClaimAsString(CLAIM_USER_ID);
        }
        return null;
    }


    /**
     * Читает из claim утверждений токена доступа имя пользователя
     *
     * @param principal класс java.security поступающий на вход контроллера
     * @return username пользователя keycloak, или null
     */
    public String getUserName(Principal principal) {

        OidcUser oidcUser = getOidcUser(principal);
        if (oidcUser != null) {
            return oidcUser.getPreferredUsername();
        }
        JwtAuthenticationToken jwtToken = getJwtToken(principal);
        if (jwtToken != null) {
            Object object = jwtToken.getTokenAttributes().get(CLAIM_USERNAME);
            return object != null ? (String) object : null;
        }
        return null;
    }


    /**
     * Читает из claim утверждений токена доступа название client id
     *
     * @param principal класс java.security поступающий на вход контроллера
     * @return название client id, или null
     */
    public String getClientId(Principal principal) {
        OidcUser oidcUser = getOidcUser(principal);
        if (oidcUser != null) {
            return oidcUser.getClaimAsString(CLAIM_CLIENT_ID);
        }
        JwtAuthenticationToken jwtToken = getJwtToken(principal);
        if (jwtToken != null) {
            Object object = jwtToken.getTokenAttributes().get(CLAIM_CLIENT_ID);
            return object != null ? (String) object : null;
        }
        return null;
    }


    public String getClientId(OidcUser oidcUser) {
        if (oidcUser != null) {
            return oidcUser.getClaimAsString(CLAIM_CLIENT_ID);
        }
        return null;
    }


    /**
     * Читает из claim утверждений токена доступа ip адрес пользователя
     *
     * @param principal класс java.security поступающий на вход контроллера
     * @return ip адрес пользователя keycloak, или null в случае ошибки
     */
    public String getIpAddress(Principal principal) {
        JwtAuthenticationToken jwtToken = getJwtToken(principal);
        if (jwtToken != null) {
            Object object = jwtToken.getTokenAttributes().get("clientHost");
            if (object != null) return (String) object;
            object = jwtToken.getTokenAttributes().get("clientAddress");
            if (object != null) return (String) object;
        }
        return null;
    }


}
