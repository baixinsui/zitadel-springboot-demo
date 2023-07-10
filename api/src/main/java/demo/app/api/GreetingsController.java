package demo.app.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.annotation.security.RolesAllowed;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
class GreetingsController {

    @Tag(name = "APIs Management",
            description = "APIs for user authentication.")
    @Operation(description = "Get current user info by authentication and print greet message.")
    @ResponseStatus(HttpStatus.OK)
    @GetMapping("/api/greet/me")
    Object greetme(Authentication auth) {
        var tokenAttributes = ((BearerTokenAuthentication) auth).getTokenAttributes();
        var message = "Greetings my friend " +
                tokenAttributes.get(StandardClaimNames.PREFERRED_USERNAME) + " " + Instant.now();
        return Map.of("message", message);
    }
}
