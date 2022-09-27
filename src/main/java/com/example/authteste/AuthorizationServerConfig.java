package com.example.authteste;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;

import java.io.InputStream;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/*
Classe de configuração do Authorization Server
 */
@Configuration
public class AuthorizationServerConfig {

    /*
    Método de configuração do authorization server definindo a tela de login default
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    /*
    Método que define o provider com o endereço do serviço
     */
    @Bean
    public ProviderSettings providerSettings(XgraccoSecurityProperties properties){
        return ProviderSettings.builder()
                .issuer(properties.getProviderUrl())
                .build();
    }

    /*
    Método com definição dos clients em memória, podendo ser substituído pela persistência em banco de dados
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder){
        RegisteredClient xgraccoCredential = RegisteredClient
                .withId("1")
                .clientId("xgracco-credential")
                .clientSecret(passwordEncoder.encode("admin123"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("READ")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .build())
                .build();
        RegisteredClient xgraccoCode = RegisteredClient
                .withId("2")
                .clientId("xgracco-code")
                .clientSecret(passwordEncoder.encode("admin124"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("READ")
                .scope("WRITE")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .reuseRefreshTokens(false)
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .build())
                .redirectUri("http://127.0.0.1:8990/authorized")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        RegisteredClient xgraccoPassoword = RegisteredClient
                .withId("3")
                .clientId("xgracco-password")
                .clientSecret(passwordEncoder.encode("admin125"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("READ")
                .scope("WRITE")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .reuseRefreshTokens(false)
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(Arrays.asList(xgraccoCredential, xgraccoCode, xgraccoPassoword));
    }

    /*
    Método para configurar a chave private da assinatura do JWT
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(JwtKeyStoreProperties properties) throws Exception {
        char[] keyStorePass = properties.getPassword().toCharArray();
        String keypairAlias = properties.getKeypairAlias();
        Resource jksLocation = properties.getJksLocation();
        InputStream inputStream = jksLocation.getInputStream();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(inputStream, keyStorePass);
        RSAKey rsaKey = RSAKey.load(keyStore, keypairAlias, keyStorePass);
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    /*
    Método para customizar o JWT
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            Authentication authentication = context.getPrincipal();
            if (authentication.getPrincipal() instanceof User user) {
                Set<String> authorities = new HashSet<>();
                for (GrantedAuthority authority : user.getAuthorities()) {
                    authorities.add(authority.getAuthority());
                }
                context.getClaims().claim("usuario_id", "sergey");
                context.getClaims().claim("email", "sergey@gmail.com");
                context.getClaims().claim("authorities", authorities);
            }
        };
    }
}
