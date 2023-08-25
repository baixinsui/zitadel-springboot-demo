package demo.app.config;

import static org.springframework.web.cors.CorsConfiguration.ALL;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

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
@Profile("jwt")
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class WebSecurityJwtConfig {

    /**
     * Configures basic security handler per HTTP session.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);

        http.headers(headersConfigurer -> headersConfigurer.addHeaderWriter(
                new XFrameOptionsHeaderWriter(
                        XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN)));

        // accept cors requests and allow preflight checks
        http.cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(
                corsConfigurationSource()));

        http.authorizeHttpRequests(arc -> {
            // add permit for swagger docs resource
            arc.requestMatchers("/swagger-ui/**", "/v3/**", "/swagger-ui.html", "/favicon.ico")
                    .permitAll();
            arc.requestMatchers("/auth/**").permitAll();
            // declarative route configuration
            arc.requestMatchers("/api/**").authenticated();
            // add additional routes
            arc.anyRequest().authenticated();
        });

        // use custom JwtAuthenticationProvider
        http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt ->
                        jwt.jwtAuthenticationConverter(grantedAuthoritiesExtractor())
                )
        );

        return http.build();
    }

    Converter<Jwt, ? extends AbstractAuthenticationToken> grantedAuthoritiesExtractor() {
        JwtAuthenticationConverter jwtAuthenticationConverter =
                new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter
                (new GrantedAuthoritiesExtractor());
        return jwtAuthenticationConverter;
    }

    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        configuration.addAllowedHeader(ALL);
        configuration.addAllowedMethod(ALL);
        configuration.addAllowedOriginPattern(ALL);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    static class GrantedAuthoritiesExtractor
            implements Converter<Jwt, Collection<GrantedAuthority>> {

        public Collection<GrantedAuthority> convert(Jwt jwt) {
            Set<GrantedAuthority> roles = new HashSet<>();
            Object rolesClaim =
                    jwt.getClaims().getOrDefault("urn:zitadel:iam:org:project:roles", null);

            if (Objects.isNull(rolesClaim)) {
                roles.add(new SimpleGrantedAuthority("user"));
            } else {
                Map<String, Object> rolesMap = (Map<String, Object>) rolesClaim;
                rolesMap.keySet()
                        .forEach(role -> roles.add(new SimpleGrantedAuthority(role)));
            }
            return roles;
        }
    }


}