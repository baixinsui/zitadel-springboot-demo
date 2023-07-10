package demo.app.config;


import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.OAuthFlow;
import io.swagger.v3.oas.annotations.security.OAuthFlows;
import io.swagger.v3.oas.annotations.security.OAuthScope;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;


/**
 * Configuration springdoc security oauth2.
 */
@OpenAPIDefinition(
        info = @Info(
                title = "Springdoc OAS3.0 - OAuth2 Resource Server - RESTful API",
                description = "Springdoc OAS3.0 - OAuth2 Resource Server - RESTful API",
                version = "v1"
        ),
        security = @SecurityRequirement(name = "OAuth2 Flow",
                scopes = {"openid", "email", "profile"})
)
@SecurityScheme(
        name = "OAuth2 Flow",
        type = SecuritySchemeType.OAUTH2,
        flows = @OAuthFlows(
                authorizationCode = @OAuthFlow(
                        authorizationUrl = "${springdoc.oAuthFlow.authorizationUrl}",
                        tokenUrl = "${springdoc.oAuthFlow.tokenUrl}",
                        scopes = {
                                @OAuthScope(name = "openid"),
                                @OAuthScope(name = "email"),
                                @OAuthScope(name = "profile")
                        }
                )
        )
)
@Configuration
public class OpenApiOauth2Config {
}
