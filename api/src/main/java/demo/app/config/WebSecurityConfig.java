package demo.app.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuration applied on all web endpoints defined for this
 * application. Any configuration on specific resources is applied
 * in addition to these global rules.
 * <p>
 * <p>
 * API接口方法权限拦截当使用 @RolesAllowed({"user", "admin"}) 时 @EnableMethodSecurity() 中需配置开启jsr250Enabled = true;
 * 当使用@Secured({"user","admin"}) 时 @EnableMethodSecurity() 中需配置开启securedEnabled = true;
 * 当使用@PreAuthorize("SPEL expression") 时,使用@EnableMethodSecurity(),默认配置开启了 prePostEnabled = true
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
class WebSecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}")
    private String introspectionUri;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret}")
    private String clientSecret;

    @Value("${logging.level.org.springframework.security:debug}")
    private String loggingLevel;

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

        // use custom OpaqueTokenIntrospector
        http.oauth2ResourceServer().opaqueToken().introspector(zitadelIntrospector());
        return http.build();
    }

    /**
     * Customize the ZitadelAuthoritiesOpaqueTokenIntrospector as the implementation class of
     * OpaqueTokenIntrospector to instead of the SpringOpaqueTokenIntrospector
     * as default implementation class.
     * <p>
     * The SpringOpaqueTokenIntrospector get roles of user from the filed 'authorities' default.
     * The IAM 'zitadel' put roles of user into other filed not 'authorities'. In this case,
     * we could not get roles of user the default SpringOpaqueTokenIntrospector.
     * So we need to customize the ZitadelAuthoritiesOpaqueTokenIntrospector, in which
     * we get the roles of user from the real filed.
     *
     * @return custom NimbusOpaqueTokenIntrospector
     */
    @Bean
    public OpaqueTokenIntrospector zitadelIntrospector() {
        return new ZitadelAuthoritiesOpaqueTokenIntrospector(this.introspectionUri, this.clientId,
                this.clientSecret, this.loggingLevel);
    }

}