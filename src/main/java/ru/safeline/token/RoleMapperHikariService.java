package ru.safeline.token;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

/**
 * Класс предназначен для реализации динамической модели сопоставления ролей методов.
 * Предполагается, что при запуске сервиса ЕЦА прокси, будет выполняться чтение справочника методов,
 * и на основе этих данных - инициализация внутренней статической карты сопоставлений методов и ролей.
 *
 * @author Vitaliy Belotserkovskii, 31.07.2024
 */
@Slf4j
@Component("token_Checker")
@RequiredArgsConstructor
@SuppressWarnings("unused")
public class RoleMapperHikariService {

    @Value("${mo.eca.role.mapping.client_id:''}")
    private String clientId;
    @Value("${mo.eca.datasource.url:''}")
    private String keycloakDatasourceUrl;
    @Value("${mo.eca.datasource.username:''}")
    private String keycloakDatasourceUsername;
    @Value("${mo.eca.datasource.password:''}")
    private String keycloakDatasourcePassword;
    @Value("${mo.eca.datasource.driver-class-name:'org.postgresql.Driver'}")
    private String keycloakDatasourceDriver;
    @Value("${mo.eca.role.mapping.enable:false}")
    private boolean isRoleMappingEnable;


    private final AccessTokenService accessTokenService;
    private final Map<String, String> roleMethodsMap = new HashMap<>();


    /**
     * Инициализирует карту сопоставлений методов и ролей.
     * Выполняется запрос в базу ЕЦА с целью получения списка сопоставлений для конкретного сервиса.
     * Для корректной работы метода, в конфигурационном файле приложения должны быть прописаны параметры:<br><br>
     * <b>mo.eca.role.mapping.enable</b> - true = активировать<br>
     * <b>mo.eca.role.mapping.client-id</b> - название сервиса, для которого запрашивается сопоставление ролей<br>
     * <b>mo.eca.datasource.url</b> - адрес БД ЕЦА<br>
     * <b>mo.eca.datasource.username</b> - логин БД ЕЦА<br>
     * <b>mo.eca.datasource.password</b> - пароль БД ЕЦА<br>
     * <b>mo.eca.datasource.driver-class-name</b> - драйвер БД, по умолчанию - org.postgresql.Driver<br>
     */
    public void initializeMapping() {

        if (StringUtils.isBlank(clientId) || StringUtils.isBlank(keycloakDatasourceUrl)
                || StringUtils.isBlank(keycloakDatasourceUsername) || StringUtils.isBlank(keycloakDatasourcePassword)) {
            log.error(">>>> initializeMapping >>>> set properties correctly for hikari cp datasource");
            return;
        }

        if (isRoleMappingEnable) {
            // загружаем карту сопоставлений ролей из ЕЦА через временный datasource = a.s.a.p
            Map<String, String> roleMap = selectMethodRoleMappingFromDatasource();
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

        if (isRoleMappingEnable) {
            if (!roleMethodsMap.isEmpty()) {
                String role = roleMethodsMap.get(methodName);
                if (StringUtils.isNotBlank(role)) return accessTokenService.isAllowedAbout(role);
            }
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


    /**
     * Выполняет инициализацию промежуточной карты сопоставления ролей и методов.
     * Для этого, устанавливается временное соединения с базой данных ЕЦА, и выполняется запрос.
     * Результатом этого запроса, является список состоящий из двух колонок:
     * название методов и назначенная методу роль.
     */
    public Map<String, String> selectMethodRoleMappingFromDatasource() {

        HikariDataSource dataSource = null;
        HikariConfig config = getHikariConfig();
        try {
            dataSource = new HikariDataSource(config);
            Connection connection = getConnection(dataSource);
            if (connection != null) {
                Map<String, String> resultMap = new HashMap<>();
                try {
                    PreparedStatement pst = connection.prepareStatement(
                            "SELECT " +
                                    "mn.\"name\", " +
                                    "mrm.key_role_token " +
                                    "FROM eca_proxy.method_nsi mn " +
                                    "LEFT JOIN eca_proxy.method_role_map mrm on mrm.uid_method = mn.uid " +
                                    "WHERE mn.client_name = ? AND mrm.uid_method = mn.uid");

                    pst.setString(1, clientId);
                    ResultSet result = pst.executeQuery();
                    while (result.next()) {
                        String methodName = result.getString(1);
                        String keyRoleToken = result.getString(2);
                        if (StringUtils.isNotBlank(methodName)
                                && StringUtils.isNotBlank(keyRoleToken)) {
                            resultMap.put(methodName, keyRoleToken);
                        }
                    }
                } catch (Exception e) {
                    log.error(">>>> getRoleMethodsMap >>>> SQL select request failed: {}", e.getMessage());
                    resultMap = null;
                }
                closeConnection(connection);
                dataSource.close();
                return resultMap;
            }
            dataSource.close();
        } catch (Exception e) {
            log.error(">>>> getRoleMethodsMap :: connection to datasource failed : {}", e.getMessage());
            if (dataSource != null) dataSource.close();
        }
        return null;
    }


    /**
     * Устанавливает соединение с datasource, который передается в метод как параметр
     *
     * @param dataSource экземпляр класса HikariDataSource
     * @return готовое соединение, или null
     */
    private @Nullable Connection getConnection(HikariDataSource dataSource) {

        Connection connection = null;
        if (dataSource != null) {
            try {
                connection = dataSource.getConnection();
            } catch (SQLException e) {
                log.error(">>>>> Не удалось установить соединение с базой данный ЕЦА: {}", e.getMessage());
            }
        }
        return connection;
    }


    /**
     * Закрывает соединение с datasource
     *
     * @param connection активное соединение
     */
    private void closeConnection(Connection connection) {

        try {
            if (connection != null) connection.close();
        } catch (SQLException e) {
            log.error(">>>>> CLOSE CONNECTION FAILED >>>>> {}", e.getMessage());
        }
    }


    /**
     * Инициализирует класс конфигурации Hikari CP соединения.
     *
     * @return экземпляр класса конфигурации
     */
    private @NotNull HikariConfig getHikariConfig() {

        HikariConfig config = new HikariConfig();

        config.setAutoCommit(true);
        config.setJdbcUrl(keycloakDatasourceUrl);
        config.setDriverClassName(keycloakDatasourceDriver);
        config.setUsername(keycloakDatasourceUsername);
        config.setPassword(keycloakDatasourcePassword);
        config.setMaximumPoolSize(5);
        config.addDataSourceProperty("cachePrepStmts", "true");
        config.addDataSourceProperty("prepStmtCacheSize", "250");
        config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");

        return config;
    }

}
