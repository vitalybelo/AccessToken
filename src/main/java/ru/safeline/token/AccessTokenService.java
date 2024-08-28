package ru.safeline.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.*;

/**
 * Класс для извлечения учетных данных и ролей пользователя из "Bearer" или "JSESSIONID" токенов доступа.
 *
 * @author Belotserkovskii Vitaly, 13.02.2024
 */
@Slf4j
@Getter
@Component
@SuppressWarnings("unused")
public class AccessTokenService {

    private static final String EMPTY_STRING = "";
    private static final String IP_DELIMITER = "##";
    private static final String TOKEN_PREFIX = "Bearer ";
    private AccessToken accessToken;


    /**
     * Проверяет доступность класса аутентификации spring security для чтения данных пользователя из токена доступа
     *
     * @return true если security context доступен
     */
    private boolean isSpringContext() {
        return Optional.ofNullable(SecurityContextHolder.getContext())
                .map(SecurityContext::getAuthentication)
                .isPresent();
    }


    /**
     * В зависимости от состава контекста безопасности spring boot security, инициализирует авторизационный
     * класс AccessToken для чтения данных пользователя из токена аутентификации.
     *
     * @return true = AccessToken инициализирован
     */
    public boolean assign() {

        accessToken = null;
        // если запрос аутентифицированный, должен быть контекст безопасности, проверим
        if (isSpringContext()) {
            // получаем класс аутентификации spring security
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication.getPrincipal();

            // Проверяем аутентификацию, выполненную по типу > BEARER
            if (principal instanceof Jwt) {
                Jwt jwt = (Jwt) principal;
                accessToken = parseAccessToken(jwt.getTokenValue());
                if (accessToken != null) return true;
            }

            // Проверяем аутентификацию, выполненную по типу > JSESSIONID
            if (principal instanceof DefaultOidcUser) {
                DefaultOidcUser user = (DefaultOidcUser) principal;
                accessToken = parseAccessToken(user.getIdToken().getTokenValue());
                if (accessToken != null) return true;
            }
        }

        // Последний вариант, попробуем вытащить токен из заголовка запроса
        HttpServletRequest request = getHttpServletRequest();
        if (request != null) {
            String token = request.getHeader("authorization");
            if (StringUtils.isNotBlank(token)) {
                accessToken = parseAccessToken(token.replace(TOKEN_PREFIX, ""));
                return accessToken != null;
            }
        }
        return false;
    }


    /**
     * Извлекает из токена значение утверждения (claim) по заданному ключу
     *
     * @param claim ключ утверждения
     * @return значение как строка
     */
    public String getAttributeAsString(String claim) {

        if (isSpringContext()) {
            // получаем класс аутентификации spring security
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication.getPrincipal();

            // Проверяем аутентификацию, выполненную по типу > BEARER
            if (principal instanceof Jwt) {
                Jwt jwt = (Jwt) principal;
                return jwt.getClaimAsString(claim);
            }

            // Проверяем аутентификацию, выполненную по типу > JSESSIONID
            if (principal instanceof DefaultOidcUser) {
                DefaultOidcUser user = (DefaultOidcUser) principal;
                return user.getClaimAsString(claim);
            }
        }
        return null;
    }


    /**
     * Инициализирует класс авторизации AccessToken из класса Java безопасности Principal.
     *
     * @param principal класс безопасности java.security
     * @return true = AccessToken инициализирован
     */
    public boolean assign(Principal principal) {

        if (principal != null) {
            JwtAuthenticationToken jwt = getJwtToken(principal);
            if (jwt != null) {
                accessToken = parseAccessToken(jwt.getToken().getTokenValue());
                if (accessToken != null) return true;
            }
            OidcUser oidc = getOidcUser(principal);
            if (oidc != null) {
                accessToken = parseAccessToken(oidc.getIdToken().getTokenValue());
                return accessToken != null;
            }
        }
        return false;
    }


    /**
     * Инициализирует класс авторизации AccessToken из класса сервлет http запроса HttpServletRequest.
     *
     * @param request экземпляр HttpServletRequest
     * @return true = AccessToken инициализирован
     */
    public boolean assign(HttpServletRequest request) {

        if (request != null) {
            String token = request.getHeader("authorization");
            if (StringUtils.isNotBlank(token)) {
                accessToken = parseAccessToken(token.replace(TOKEN_PREFIX, ""));
                return accessToken != null;
            }
        }
        return false;
    }


    /**
     * @return Возвращает идентификатор пользователя keycloak
     */
    public String getUserId() {
        return assign() ? accessToken.getUserId() : null;
    }


    /**
     * @return Возвращает идентификатор сеанса авторизации пользователя в keycloak
     */
    public String getSessionId() {
        return assign() ? accessToken.getSessionId() : null;
    }


    /**
     * @return Возвращает имя пользователя, использующееся как login для входа
     */
    public @NotNull String getLogin() {
        return assign() ? accessToken.getLogin() : EMPTY_STRING;
    }


    /**
     * @return Возвращает имя пользователя
     */
    public @NotNull String getFirstName() {
        return assign() ? accessToken.getFirstName() : EMPTY_STRING;
    }


    /**
     * @return Возвращает отчество пользователя
     */
    public @NotNull String getMiddleName() {
        return assign() ? accessToken.getMiddleName() : EMPTY_STRING;
    }


    /**
     * @return Возвращает фамилию пользователя
     */
    public @NotNull String getFamilyName() {
        return assign() ? accessToken.getFamilyName() : EMPTY_STRING;
    }


    /**
     * @return Возвращает полное имя пользователя: имя, отчество и фамилию
     */
    public @NotNull String getFullName() {

        if (assign()) {
            String space = " ";
            String firstName = accessToken.getFirstName();
            String middleName = accessToken.getMiddleName();
            String familyName = accessToken.getFamilyName();
            StringBuilder fio = new StringBuilder();
            if (StringUtils.isBlank(firstName)) fio.append(getLogin());
            else fio.append(getFirstName());
            if (StringUtils.isNotBlank(middleName)) fio.append(space).append(middleName);
            if (StringUtils.isNotBlank(familyName)) fio.append(space).append(familyName);
            return fio.toString();
        }
        return EMPTY_STRING;
    }


    /**
     * @return Возвращает строку с электронной почтой пользователя
     */
    public @NotNull String getEmail() {
        return assign() ? accessToken.getEmail() : EMPTY_STRING;
    }


    /**
     * @return Возвращает строку с номером телефона пользователя
     */
    public @NotNull String getPhone() {
        return assign() ? accessToken.getPhone() : EMPTY_STRING;
    }


    /**
     * @return Возвращает строку с названием департамента пользователя
     */
    public @NotNull String getDepartment() {
        return assign() ? accessToken.getDepartment() : EMPTY_STRING;
    }


    /**
     * @return Возвращает строку с названием должности пользователя
     */
    public @NotNull String getPosition() {
        return assign() ? accessToken.getPosition() : EMPTY_STRING;
    }


    /**
     * @return Возвращает список разрешенных ip адресов пользователя
     */
    public @NotNull List<String> getIpAddress() {

        if (assign()) {
            String ipString = accessToken.getIpAddress();
            if (StringUtils.isNotBlank(ipString)) {
                String[] ips = ipString.split(IP_DELIMITER);
                return Arrays.asList(ips);
            }
        }
        return Collections.emptyList();
    }


    /**
     * @return Возвращает количество разрешенных одновременно сессия для пользователя
     */
    public Integer getMaxSession() {
        return assign() ? accessToken.getMaxSessions() : 0;
    }


    /**
     * @return Возвращает максимальное время простоя для пользователя
     */
    public Integer getMaxIdleTime() {
        return assign() ? accessToken.getMaxIdleTime() : 0;
    }


    /**
     * @return извлекает из токена список всех значений realm ролей, которые были назначены пользователю.
     */
    public List<String> getRealmRoles() {
        return assign() ? streamRealmRoles() : Collections.emptyList();
    }


    /**
     * @return извлекает из токена список всех значений ролей сервисов, которые предоставлены пользователю
     */
    public List<String> getClientRoles() {
        return assign() ? streamClientRoles() : Collections.emptyList();
    }


    /**
     * @return извлекает и возвращает из карты ролей области все значения
     */
    private @NotNull List<String> streamRealmRoles() {

        List<String> roles = new ArrayList<>();
        try {
            accessToken.getRealmRolesMap()
                    .values()
                    .forEach(roles::addAll);
        } catch (Exception ignored) {
        }
        return roles;
    }


    /**
     * @return извлекает и возвращает из карты ролей сервисов все значения
     */
    private @NotNull List<String> streamClientRoles() {

        List<String> roles = new ArrayList<>();
        try {
            accessToken.getClientRolesMap()
                    .values()
                    .forEach(map -> map.values().forEach(roles::addAll));
        } catch (Exception ignored) {
        }
        return roles;
    }


    /**
     * @return извлекает из токена полный список ролей (realm и clients), которые были назначены пользователю
     */
    public List<String> getAllRoles() {

        if (assign()) {
            List<String> allRoles = streamRealmRoles();
            allRoles.addAll(streamClientRoles());
            return allRoles;
        }
        return Collections.emptyList();
    }


    /**
     * Выполняет проверку на наличие у пользователя требуемой роли только в списке ролей сервисов
     *
     * @param roleString строка требуемой роли
     * @return true если роль присутствует в токене
     */
    public boolean isAllowed(String roleString) {
        return assign() && getClientRoles().contains(roleString);
    }


    /**
     * Выполняет проверку на наличие у текущего пользователя хотя бы одной роли из заданного параметром
     * списка. Проверка выполняется среди всех ролей сервисов, назначенных пользователю.
     *
     * @param roles требуемый список ролей
     * @return true если хотя-бы одна роль из списка требуемых имеется у пользователя
     */
    public boolean anyMatch(List<String> roles) {
        if (assign()) {
            return streamClientRoles().stream().anyMatch(roles::contains);
        }
        return false;
    }


    public boolean allMatch(List<String> roles) {
        if (assign()) {
            return new HashSet<>(roles).containsAll(streamClientRoles());
        }
        return false;
    }


    /**
     * Выполняет проверку на отсутствие у пользователя требуемой роли только в списке ролей сервисов
     *
     * @param roleString строка требуемой роли
     * @return true если роль отсутствует в токене
     */
    public boolean isForbidden(String roleString) {
        return !isAllowed(roleString);
    }


    /**
     * Выполняет проверку на наличие у пользователя требуемой роли в списке ролей сервисов (client roles)
     * или списке ролей области (realm roles)
     *
     * @param roleString строка требуемой роли
     * @return true если роль присутствует в токене
     */
    public boolean isAllowedAbout(String roleString) {
        return assign() && getAllRoles().contains(roleString);
    }


    /**
     * Выполняет проверку на отсутствие у пользователя требуемой роли в списке ролей сервисов (client roles)
     * или списке ролей области (realm roles)
     *
     * @param roleString строка требуемой роли
     * @return true если роль отсутствует в токене
     */
    public boolean isForbiddenAbout(String roleString) {
        return !isAllowedAbout(roleString);
    }


    /**
     * Метод извлекает экземпляр класса авторизации AccessToken из payload токена доступа keycloak.
     *
     * @param tokenString строка с токеном доступа keycloak, без префикса Bearer
     * @return экземпляр класса AccessToken, или null в случае ошибки
     */
    private AccessToken parseAccessToken(String tokenString) {

        AccessToken accessToken = null;
        if (!StringUtils.isBlank(tokenString)) {
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String[] chunks = tokenString.split("\\.");
            if (chunks.length > 1) {
                //String header = new String(decoder.decode(chunks[0]));
                String payload = new String(decoder.decode(chunks[1]));
                try {
                    ObjectMapper objectMapper = new ObjectMapper();
                    accessToken = objectMapper.readValue(payload, AccessToken.class);
                } catch (Exception e) {
                    log.info(">>> Ошибка парсинга токена доступа: {}", e.getMessage());
                }
            }
        }
        return accessToken;
    }


    /**
     * Переопределяет экземпляр класса Principal в экземпляр токена доступа типа Bearer: JwtAuthenticationToken
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
     * Переопределяет экземпляр класса Principal в экземпляр токена доступа типа JSESSIONID: OidcUser
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
     * Извлекает из контекста сервлета экземпляр класса HttpServletRequest
     *
     * @return экземпляр класса HttpServletRequest
     */
    private @Nullable HttpServletRequest getHttpServletRequest() {

        if (Optional.ofNullable((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                .map(ServletRequestAttributes::getRequest).isPresent()) {
            return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        }
        return null;
    }

}
