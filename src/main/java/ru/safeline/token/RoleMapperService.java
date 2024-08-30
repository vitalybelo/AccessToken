package ru.safeline.token;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * Класс предназначен для реализации динамической модели сопоставления ролей методов. Предполагается,
 * что при запуске каждого приложения ЕИС ГОЗ, первоначально будет выполняться чтение справочника методов,
 * и на основе полученных данных для сервиса, будет инициализирована внутренняя карта авторизации
 * для сопоставлений методов и назначенных ролей.
 *
 * @author Vitaliy Belotserkovskii, 29.08.2024
 */
@Slf4j
@Component("tokenChecker")
@SuppressWarnings("unused")
@RequiredArgsConstructor
public class RoleMapperService {

    @Value("${mo.eca.role.mapping.client-id:''}")
    private String clientId ;
    @Value("${mo.eca.role.mapping.method-url:''}")
    private String roleMappingMethodUrl;
    @Value("${mo.eca.role.mapping.enable:false}")
    private boolean isRoleMappingEnable;


    private final AccessTokenService accessTokenService;
    private final KeycloakTokenService keycloakTokenService;

    private final RestTemplate restTemplate = new RestTemplate();
    private final Map<String, String> roleMethodsMap = new HashMap<>();

    @Getter
    private boolean isRoleMethodsMapped = false;

    /**
     * Инициализирует карту сопоставлений методов и ролей.
     * Выполняется запрос в базу ЕЦА с целью получения списка сопоставлений для конкретного сервиса.
     * Конечная точка запроса - http://{eca_proxy_ip:port}/eca/api/role_code_mapper<br><br>
     * Для корректной работы метода, в конфигурационном файле приложения должны быть прописаны три
     * параметра:<br><br>
     * <b>mo.eca.role.mapping.enable</b> - true = активировано<br>
     * <b>mo.eca.role.mapping.client-id</b> - название сервиса, для которого запрашивается сопоставление ролей<br>
     * <b>mo.eca.role.mapping.method-url</b> - endpoint метода ЕЦА<br>
     */
    @SuppressWarnings("unchecked")
    public void initializeMapping() {

        if (StringUtils.isBlank(clientId) || StringUtils.isBlank(roleMappingMethodUrl)) {
            log.error(">>>> initializeMapping >>>> set properties correctly for http request");
            return;
        }

        if (isRoleMappingEnable) {

            Map<String, String> roleMap = null;
            StringBuilder sb = new StringBuilder(roleMappingMethodUrl);
            if (!roleMappingMethodUrl.endsWith("/")) sb.append("/");
            sb.append(clientId);

            try {
                HttpHeaders headers = keycloakTokenService.getOauth2Headers();
                HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
                ResponseEntity<Object> result = restTemplate.exchange(sb.toString(), HttpMethod.GET, requestEntity,
                        Object.class, new ParameterizedTypeReference<>() {
                        });

                if (result.getStatusCode().equals(HttpStatus.OK) && result.getBody() != null) {
                    if (result.getBody() instanceof Map) {
                        roleMap = (Map<String, String>) result.getBody();
                        isRoleMethodsMapped = true;
                    }
                } else {
                    log.warn(">>>> Ошибка загрузки карты сопоставлений :: {}", result.getStatusCode());
                    isRoleMethodsMapped = false;
                }
            } catch (Exception ignore) {
            }
            if (roleMap == null) {
                log.info(">>> Не удалось прочитать карту сопоставлений для методов сервиса: \"{}\"", clientId);
                return;
            }
            // запрос выполнен успешно, карта сопоставлений получена, теперь проверим наличие в ней сопоставлений
            roleMethodsMap.clear();
            if (!roleMap.isEmpty()) {
                roleMethodsMap.putAll(roleMap);
                log.info(">>> Карта авторизации инициализирована, количество загруженных сопоставлений = {}", roleMethodsMap.size());
                return;
            }
            log.info(">>> Карта авторизации пустая, не существует сопоставлений для методов сервиса: \"{}\"", clientId);
        } else {
            log.info(">>> Динамическое сопоставление ролей отключено для методов данного сервиса");
        }
    }


    /**
     * Выполняет проверку на наличии прав.<br>
     * По заданному наименованию метода, в карте авторизации ищется сопоставление для получения значения
     * роли. Если сопоставление не найдено, это означает что метод не требует авторизации по какой-нибудь
     * роли. Если сопоставление найдено, проверяется наличие соответствующего значения роли в токене
     * доступа пользователя, от имени которого выполняется запрос в сервис.
     *
     * @param methodName строка с названием метода
     * @return значение true если выполнение метода разрешается
     */
    public boolean isAllowed(@NotNull String methodName) {

        if (isRoleMappingEnable && !roleMethodsMap.isEmpty()) {
                String role = roleMethodsMap.get(methodName);
                if (StringUtils.isNotBlank(role)) return accessTokenService.isAllowedAbout(role);
            }

        return true;
    }


    /**
     * Выполняет проверку на отсутствие прав
     *
     * @param methodName строка с названием метода
     * @return значение true если выполнение метода запрещено
     */
    public boolean isForbidden(@NotNull String methodName) {
        return !isAllowed(methodName);
    }


}
