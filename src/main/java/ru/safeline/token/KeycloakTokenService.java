package ru.safeline.token;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

/**
 * Авторизационный класс для получения токена доступа, который также создает и возвращает
 * заголовок запроса Oauth2, необходимый для выполнения запроса.
 *
 * @author Vitaliy Belotserkovskii, исправлено 07.08.2024
 */
@Slf4j
@Service
@RequiredArgsConstructor
@SuppressWarnings("unused")
public class KeycloakTokenService {

    private final Keycloak keycloak;

    /**
     * Метод запрашивает токен доступа к административной консоли keycloak, а после получения
     * формирует заголовок для Oauth2 аутентификации с bearer токеном
     *
     * @return экземпляр класса заголовка http запроса HttpHeaders
     */
    public HttpHeaders getOauth2Headers() {

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Authorization", "Bearer " + getAccessToken());
        return httpHeaders;
    }

    /**
     * Запрашивает в keycloak токен доступа и возвращает его как строку
     * @return строка с токеном доступа
     */
    public String getAccessToken() {
        return keycloak.tokenManager().getAccessTokenString();
    }

}
