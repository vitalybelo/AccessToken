package ru.safeline.token;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Service;

import java.util.*;


/**
 * Класс администрирования keycloak admin-client.<br>Специально для библиотеки AccessToken.
 *
 * @author Vitali Belotserkovskii, 01.10.2024
 */
@Slf4j
@Service
@RequiredArgsConstructor
@SuppressWarnings("unused")
public class KeycloakAdminService {

    private final RealmResource realmResource;


    /**
     * Выполняет сбор всех атрибутов, со всех групп, участником которых является системный пользователь
     * сервиса. Полученная карта хранит в качестве ключа - ключ атрибута, а в качестве значения - уникальный
     * набор значений атрибутов. Метод необходим для того, чтобы определить, на какие обменники и очереди
     * подписан переданный в качестве параметра сервис ЕЦА
     *
     * @param clientId идентификатор сервиса (например: mo-nsi)
     * @return карту с наборами значений (обменников, очередей, ключей)
     */
    public Map<String, List<String>> getClientRabbitRights(String clientId) {

        Map<String, Set<String>> attributes = new HashMap<>();
        if (StringUtils.isNotBlank(clientId)) { // проверка на пустой входной параметр

            List<ClientRepresentation> clientApplicants = realmResource.clients().findByClientId(clientId);
            if (CollectionUtils.isNotEmpty(clientApplicants)) { // проверяем наличие сервисов с похожими именами

                ClientRepresentation client = clientApplicants.stream()
                        .filter(c -> c.getClientId().equals(clientId))
                        .findFirst()
                        .orElse(null);

                if (client != null && client.isServiceAccountsEnabled()) { // нужный сервис найден

                    String serviceAccount = "service-account-" + clientId;
                    List<UserRepresentation> userApplicants = realmResource.users().searchByUsername(serviceAccount, true);

                    if (CollectionUtils.isNotEmpty(userApplicants)) { // системный пользователь сервиса типа найден
                        UserRepresentation user = userApplicants.stream()
                                .filter(u -> u.getUsername().equals(serviceAccount))
                                .findFirst()
                                .orElse(null);

                        if (user != null) { // "останется только один" и дальше музыка из фильма HighLander (Queen)

                            UserResource userResource = realmResource.users().get(user.getId());
                            List<GroupRepresentation> userGroups = userResource.groups(0, Integer.MAX_VALUE, false);

                            if (CollectionUtils.isNotEmpty(userGroups)) {
                                // все группы пользователя найдены - начинаем собирать атрибуты
                                try {
                                    userGroups.stream()
                                            .map(GroupRepresentation::getAttributes)
                                            .forEach(map -> map.forEach((key, value)
                                                    -> value.forEach(string
                                                    -> attributes.computeIfAbsent(key, k -> new HashSet<>()).add(string))));

                                    if (!attributes.isEmpty()) {
                                        Map<String, List<String>> resultMap = new HashMap<>();
                                        attributes.forEach((key, value) -> resultMap.put(key, new ArrayList<>(value)));
                                        return resultMap;
                                    }
                                } catch (Exception e) {
                                    log.error(">>>> getClientRabbitRights >>>> {}", e.getMessage());
                                }
                            }
                        }
                    }
                }
            }
        }
        return new HashMap<>();
    }


}
