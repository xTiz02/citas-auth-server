package org.prd.citasmedicasback.persistence.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;


@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ClientApp {

    private Long id;
    private String clientId;
    private String clientSecret;
    private String clientName;

    private List<String> authenticationMethods = new ArrayList<>();

    private List<String> authorizationGrantTypes;

    private List<String> postLogoutRedirectUris;

    private List<String> redirectUris;

    private List<String> scopes;
    private int durationInMinutes;
    private boolean requireProofKey;


    public static RegisteredClient toRegisteredClient(ClientApp clientApp) {
        return RegisteredClient.withId(clientApp.getId().toString())
                .clientId(clientApp.getClientId())
                //.clientIdIssuedAt(null)
                .clientSecret(clientApp.getClientSecret())
                //.clientSecretExpiresAt(null)
                .clientName(clientApp.getClientName())
                .authorizationGrantTypes(gts->{
                    gts.addAll(clientApp.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::new).toList());
                })
                .clientAuthenticationMethods(cams->{
                    cams.addAll(clientApp.getAuthenticationMethods().stream().map(ClientAuthenticationMethod::new).toList());
                })
                .redirectUris(rus ->{
                    rus.addAll(clientApp.getRedirectUris());
                })
                .postLogoutRedirectUris(plrus->{
                    plrus.addAll(clientApp.getPostLogoutRedirectUris());
                })
                .scopes(scopes->{
                    scopes.addAll(clientApp.getScopes());
                })
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(clientApp.isRequireProofKey())
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(clientApp.getDurationInMinutes()))
                        .refreshTokenTimeToLive(Duration.ofMinutes(clientApp.getDurationInMinutes() * 4L))
                        .build())
                .build();
    }
}