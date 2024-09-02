package ru.safeline.token;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

import java.util.LinkedHashMap;
import java.util.List;

/**
 * Класс описывающий сущность токена доступа пользователя keycloak. Поля по необходимости можно добавлять.
 *
 * @author Vitalii Belotserkovskii, 16.10.2023
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@SuppressWarnings("unused")
@JsonIgnoreProperties(ignoreUnknown = true)
public class AccessToken {

    private String exp;
    private String iat;
    private String jti;
    private String iss;
    private Object aud;

    @JsonProperty("sub")
    private String userId;

    private String typ;

    @JsonProperty("azp")
    private String clientId;

    @JsonProperty("sid")
    private String sessionId;

    @JsonProperty("session_state")
    private String sessionState;

    @JsonProperty("realm_access")
    private LinkedHashMap<String, List<String>> realmRolesMap;

    @JsonProperty("resource_access")
    private LinkedHashMap<String, LinkedHashMap<String, List<String>>> clientRolesMap;

    @JsonProperty("given_name")
    private String firstName;

    @JsonProperty("middle_name")
    private String middleName;

    @JsonProperty("family_name")
    private String familyName;

    private String name;

    @JsonProperty("preferred_username")
    private String login;

    private String email;
    private String phone;
    private String department;
    private String position;

    @JsonProperty("email_verified")
    private boolean emailVerified;

    @JsonProperty("ip_address")
    private String ipAddress;

    @JsonProperty("max_sessions")
    private Integer maxSessions;

    @JsonProperty("max_idle_time")
    private Integer maxIdleTime;


    @JsonSetter("max_sessions")
    public void setMaxSessions(String maxSessions) {
        if (StringUtils.isNotBlank(maxSessions)) {
            try {
                this.maxSessions = Integer.parseInt(maxSessions);
                return;
            } catch (NumberFormatException ignored) {
            }
        }
        this.maxSessions = 0;
    }

    @JsonSetter("max_idle_time")
    public void setMaxIdleTime(String maxIdleTime) {
        if (StringUtils.isNotBlank(maxIdleTime)) {
            try {
                this.maxIdleTime = Integer.parseInt(maxIdleTime);
                return;
            } catch (NumberFormatException ignored) {
            }
        }
        this.maxIdleTime = 0;
    }

    @JsonGetter("preferred_username")
    public String getLogin() {
        return getNotNullString(login);
    }

    @JsonGetter("given_name")
    public String getFirstName() {
        return getNotNullString(firstName);
    }

    @JsonGetter("middle_name")
    public String getMiddleName() {
        return getNotNullString(middleName);
    }

    @JsonGetter("family_name")
    public String getFamilyName() {
        return getNotNullString(familyName);
    }

    @JsonGetter("email")
    public String getEmail() {
        return getNotNullString(email);
    }

    @JsonGetter("phone")
    public String getPhone() {
        return getNotNullString(phone);
    }

    @JsonGetter("department")
    public String getDepartment() {
        return getNotNullString(department);
    }

    @JsonGetter("position")
    public String getPosition() {
        return getNotNullString(position);
    }

    @JsonGetter("ip_address")
    public String getIpAddress() {
        return getNotNullString(ipAddress);
    }

    private @NotNull String getNotNullString(String string) {
        return string == null ? "" : string;
    }

    @JsonGetter("max_idle_time")
    public Integer getMaxIdleTime() {
        return maxIdleTime == null ? 0 : maxIdleTime;
    }

    @JsonGetter("max_sessions")
    public Integer getMaxSessions() {
        return maxSessions == null ? 0 : maxSessions;
    }
}
