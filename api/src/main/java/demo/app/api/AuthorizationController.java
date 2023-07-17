/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Huawei Inc.
 *
 */

package demo.app.api;

import demo.app.model.TokenResponse;
import demo.app.service.ZitadelAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;


/**
 * REST interface methods for authorization.
 */
@Slf4j
@RestController
@CrossOrigin
public class AuthorizationController {

    private final ZitadelAuthService zitadelAuthService;

    public AuthorizationController(ZitadelAuthService zitadelAuthService) {
        this.zitadelAuthService = zitadelAuthService;
    }


    @Tag(name = "Auth Management",
            description = "APIs for user authentication.")
    @Operation(description = "Get and redirect authorization url for user to authorize.")
    @ResponseStatus(HttpStatus.OK)
    @GetMapping("/auth/authorize")
    void redirectAuthorizeUrl(HttpServletResponse response) throws IOException {
        String authorizeUrl = zitadelAuthService.getAuthorizeUrl();
        response.sendRedirect(authorizeUrl);
    }

    @Tag(name = "Auth Management",
            description = "APIs for user authentication.")
    @Operation(description = "Get token info by authorization code.")
    @ResponseStatus(HttpStatus.OK)
    @GetMapping(value = "/auth/token", produces = MediaType.APPLICATION_JSON_VALUE)
    TokenResponse getAccessToken(
            @Parameter(name = "code", required = true, description = "The authorization code.")
                    String code,
            @Parameter(name = "state", description = "Opaque value used to maintain state.")
                    String state) {
        return zitadelAuthService.getAccessToken(code);
    }


}
