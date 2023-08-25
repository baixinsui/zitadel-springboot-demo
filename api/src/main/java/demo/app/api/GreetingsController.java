package demo.app.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import demo.app.model.CurrentUserInfo;
import demo.app.service.ZitadelAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.annotation.Resource;
import jakarta.annotation.security.RolesAllowed;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin
@RestController
class GreetingsController {

    private static final ObjectMapper mapper = new ObjectMapper();
    @Resource
    ZitadelAuthService zitadelAuthService;

    @Tag(name = "APIs Management",
            description = "APIs for user authentication.")
    @Operation(description = "Get current user info by authentication and print greet message.")
    @ResponseStatus(HttpStatus.OK)
    @GetMapping("/api/greet/me")
    @RolesAllowed({"user", "admin"})
    Object greetme() throws JsonProcessingException {
        CurrentUserInfo userInfo = zitadelAuthService.getCurrentUserInfo();
        var message = "Greetings my friend:" +
                mapper.writeValueAsString(userInfo) + " NowTime:" + Instant.now();
        return Map.of("message", message);
    }

    @Tag(name = "APIs Management",
            description = "APIs for user authentication.")
    @Operation(description = "Get current user info by authentication and print greet message.")
    @ResponseStatus(HttpStatus.OK)
    @GetMapping("/api/greet/me2")
    @PreAuthorize("hasAnyRole('user','admin')")
    Object greetme2(Authentication auth) throws JsonProcessingException {
        CurrentUserInfo userInfo = zitadelAuthService.getCurrentUserInfo();
        var message = "Greetings my friend:" +
                mapper.writeValueAsString(userInfo) + " NowTime:" + Instant.now();
        return Map.of("message", message);
    }

    @Tag(name = "APIs Management",
            description = "APIs for user authentication.")
    @Operation(description = "Get current user info by authentication and print greet message.")
    @ResponseStatus(HttpStatus.OK)
    @GetMapping("/api/greet/me4")
    @PreAuthorize("hasAnyAuthority('user','admin')")
    Object greetme4() throws JsonProcessingException {
        CurrentUserInfo userInfo = zitadelAuthService.getCurrentUserInfo();
        var message = "Greetings my friend:" +
                mapper.writeValueAsString(userInfo) + " NowTime:" + Instant.now();
        return Map.of("message", message);
    }

    @Tag(name = "APIs Management",
            description = "APIs for user authentication.")
    @Operation(description = "Get current user info by authentication and print greet message.")
    @ResponseStatus(HttpStatus.OK)
    @GetMapping("/api/greet/me3")
    // 同时使用多个权限拦截，用户权限满足其中一个即可进入方法
    @Secured({"user", "admin"})
    Object greetme3() throws JsonProcessingException {
        CurrentUserInfo userInfo = zitadelAuthService.getCurrentUserInfo();
        var message = "Greetings my friend:" +
                mapper.writeValueAsString(userInfo) + " NowTime:" + Instant.now();
        return Map.of("message", message);
    }
}
