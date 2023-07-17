package demo.app.intropector;


import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.util.CollectionUtils;

@Slf4j
public class ZitadelAuthoritiesOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private static final String ATTRIBUTE_USERNAME = "username";
    private static final String ATTRIBUTE_USERID = "sub";
    private static final String ATTRIBUTE_ROLES = "urn:zitadel:iam:org:project:roles";
    /**
     * API接口方法使用 @RolesAllowed({"user", "admin"}) 或 @PreAuthorize("hasAnyRole('user','admin')") 做权限拦截时需要加前缀ROLE_;
     * 使用@Secured({"user","admin"}) 或 @PreAuthorize("hasAnyAuthority('user','admin')")时不需要加前缀.
     */
//    private static final String ROLE_PREFIX = "ROLE_";
    private static final String ROLE_PREFIX = "";
    private static final String DEFAULT_ROLE = "user";

    private final OpaqueTokenIntrospector delegate;

    private final boolean dedugEnabled;

    public ZitadelAuthoritiesOpaqueTokenIntrospector(String introspectionUri, String clientId,
                                                     String clientSecret, String loggingLevel) {
        delegate = new NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
        dedugEnabled = StringUtils.equalsIgnoreCase(loggingLevel, "debug")
                || StringUtils.equalsIgnoreCase(loggingLevel, "trace");

    }

    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2AuthenticatedPrincipal principal = this.delegate.introspect(token);
        return new DefaultOAuth2AuthenticatedPrincipal(
                principal.getName(), principal.getAttributes(), extractAuthorities(principal));
    }

    private Collection<GrantedAuthority> extractAuthorities(
            OAuth2AuthenticatedPrincipal principal) {
        Collection<GrantedAuthority> roleSet;
        JSONObject roleObject = principal.getAttribute(ATTRIBUTE_ROLES);
        String userName = principal.getAttribute(ATTRIBUTE_USERNAME);
        String userId = principal.getAttribute(ATTRIBUTE_USERID);
        if (Objects.isNull(roleObject)) {
            roleSet = Set.of(new SimpleGrantedAuthority(ROLE_PREFIX + DEFAULT_ROLE));
            if (this.dedugEnabled) {
                log.debug("Get user [id:{},userName:{}] granted authorities is null,"
                        + " set default ROLE_user", userId, userName);
            }
        } else {
            Set<String> roles = roleObject.keySet();
            if (CollectionUtils.isEmpty(roles)) {
                roleSet = Set.of(new SimpleGrantedAuthority(ROLE_PREFIX + DEFAULT_ROLE));
                if (this.dedugEnabled) {
                    log.debug("Get user [id:{},userName:{}] granted authorities is empty,"
                            + " set default ROLE_user", userId, userName);
                }
            } else {
                roleSet = roles.stream()
                        .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                        .collect(Collectors.toSet());
                if (this.dedugEnabled) {
                    log.debug("Get user [id:{},userName:{}] granted authorities:{},",
                            userId, userName, roleSet);
                }
            }
        }
        return roleSet;
    }
}