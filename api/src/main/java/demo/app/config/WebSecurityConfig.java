package demo.app.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuration applied on all web endpoints defined for this
 * application. Any configuration on specific resources is applied
 * in addition to these global rules.
 */
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
class WebSecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}")
    private String introspectionUri;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret}")
    private String clientSecret;

    /**
     * Configures basic security handler per HTTP session.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(arc -> {
            // add permit for swagger docs resource
            arc.requestMatchers("/swagger-ui/**", "/v3/**", "/swagger-ui.html", "/favicon.ico")
                    .permitAll();
            // declarative route configuration
            arc.requestMatchers("/api/**").authenticated();
            // add additional routes
            arc.anyRequest().authenticated();
        });

        http.oauth2ResourceServer(oauth2 -> oauth2
                .opaqueToken(opaque -> opaque
                        .introspectionUri(this.introspectionUri)
                        .introspectionClientCredentials(this.clientId, this.clientSecret)
                )
        );

        return http.build();
    }

}