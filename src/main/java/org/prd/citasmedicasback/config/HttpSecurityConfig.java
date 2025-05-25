package org.prd.citasmedicasback.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.prd.citasmedicasback.config.handler.CustomLogoutHandler;
import org.prd.citasmedicasback.config.handler.CustomLogoutSuccessHandler;
import org.prd.citasmedicasback.util.RoleEnum;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class HttpSecurityConfig {

    //    private final UserRepositoryOAuth2UserHandler userRepositoryOAuth2UserHandler;
//
//    public HttpSecurityConfig(UserRepositoryOAuth2UserHandler userRepositoryOAuth2UserHandler) {
//        this.userRepositoryOAuth2UserHandler = userRepositoryOAuth2UserHandler;
//    }
//

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        //Oauth2 autorización +
        //OpenID Autenticación +
        //OpenID Connect 1.0 =
        /*
         * Al habilitar OpenID Connect 1.0 se configurará automáticamente la compatibilidad del
         * servidor de recursos que permite que las solicitudes de información del usuario se
         * autentiquen con tokens de acceso.*/
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();


        http.cors(Customizer.withDefaults());
        http.csrf(AbstractHttpConfigurer::disable);
        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                .oidc(Customizer.withDefaults()) //Enable OpenID Connect 1.0
                );
        http.authorizeHttpRequests((authorize) -> {
                authorize.requestMatchers("/login").permitAll();
                authorize.anyRequest().authenticated();
        }
        );
        http.exceptionHandling((exceptions) -> exceptions
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        );
        http.oauth2ResourceServer((oauth2) -> oauth2
                .jwt(Customizer.withDefaults())
        );
    return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(
            CustomLogoutSuccessHandler logoutSuccessHandler,
            CustomLogoutHandler customLogoutHandler, HttpSecurity http)
            throws Exception {

        http.cors(Customizer.withDefaults());
        http.csrf(AbstractHttpConfigurer::disable);
//        http.requestCache(RequestCacheConfigurer::disable);
        http.authorizeHttpRequests((authorize) -> {
                    authorize.requestMatchers("/login").permitAll();

                    authorize.anyRequest().authenticated();
                })
                .formLogin((formLogin) -> formLogin
                        .loginPage("/login")
                        .permitAll()
                );
//        http.oauth2Login((oauth2Login) -> oauth2Login
//                .loginPage("/login")
//                .permitAll()
//
//        );
        http.logout((logout) -> logout
                .logoutSuccessUrl("http://localhost:5173/authorized?logout=logout_action")
                .deleteCookies("JSESSIONID")
                .clearAuthentication(true)
                .invalidateHttpSession(true)
//                .addLogoutHandler(customLogoutHandler)
//                .logoutSuccessHandler(logoutSuccessHandler)
        );

        return http.build();
    }


//    public LogoutSuccessHandler logoutSuccessHandler() {
//        return new CustomLogoutSuccessHandler();
//    }
//
//    private AuthenticationSuccessHandler authenticationSuccessHandler(){
//        return new FederatedIdentityAuthenticationSuccessHandler(userRepositoryOAuth2UserHandler);
//    }

    /*
     * tokens->{
     *       JWT = HEADER.PAYLOAD.SIGNATURE  HS256* FIRMADO
     *       JWS = JWK                       RS256* ENCRIPTADO
     * }*/
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8085") //Pregunta como decodificar el token
                .build();
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource(@Value("${spring.web.cors.allowed-origins}") String allowedOrigins) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration cors = new CorsConfiguration();
        cors.addAllowedHeader("*");
        cors.addAllowedMethod("*");
        cors.setAllowCredentials(true);
        cors.addAllowedOrigin(allowedOrigins);
        source.registerCorsConfiguration("/**", cors);
        return source;
    }
}