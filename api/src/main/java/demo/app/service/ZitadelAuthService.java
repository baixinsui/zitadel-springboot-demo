/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Huawei Inc.
 *
 */

package demo.app.service;

import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import demo.app.model.CurrentUserInfo;
import demo.app.model.TokenResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Service for authorization.
 */
@Slf4j
@Service
public class ZitadelAuthService {

    private static final String USER_ID_KEY = "sub";
    private static final String USER_NAME_KEY = "preferred_username";
    private static final String METADATA_KEY = "urn:zitadel:iam:user:metadata";
    private static final Map<String, String> CODE_CHALLENGE_MAP = initCodeChallengeMap();

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${authorization-server-endpoint}")
    private String iamServerEndpoint;

    @Value("${authorization-swagger-ui-client-id}")
    private String clientId;

    @Value("${spring.profiles.active:jwt}")
    private String authType;

    private static Map<String, String> initCodeChallengeMap() {
        Map<String, String> map = new HashMap<>(2);
        try {
            SecureRandom sr = new SecureRandom();
            byte[] code = new byte[32];
            sr.nextBytes(code);
            String verifier = Base64.encodeBase64String(code);
            log.info("code_verifier:{}", verifier);
            map.put("code_verifier", verifier);

            byte[] bytes = verifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytes, 0, bytes.length);
            byte[] digest = md.digest();
            String challenge = Base64.encodeBase64URLSafeString(digest);
            log.info("code_challenge:{}", challenge);
            map.put("code_challenge", challenge);
        } catch (NoSuchAlgorithmException e) {
            log.error("initCodeChallengeMap error.", e);
        }
        return map;

    }

    /**
     * Get authorize url for user.
     *
     * @return authorize url
     */
    public String getAuthorizeUrl() {
        StringBuilder stringBuilder = new StringBuilder();
        String redirectUrl = ServletUriComponentsBuilder.fromCurrentContextPath()
                .build().toUriString() + "/auth/token";
        stringBuilder.append(iamServerEndpoint).append("/oauth/v2/authorize").append("?")
                .append("client_id=").append(clientId).append("&")
                .append("response_type=code").append("&")
                .append("scope=openid").append("&")
                .append("redirect_uri=").append(redirectUrl).append("&")
                .append("code_challenge_method=S256").append("&")
                .append("code_challenge=").append(CODE_CHALLENGE_MAP.get("code_challenge"));
        return stringBuilder.toString();
    }

    /**
     * Get access token from IAM.
     *
     * @param code The authorization code
     * @return Model of access token.
     */
    public TokenResponse getAccessToken(String code) {
        String tokenUrl = iamServerEndpoint + "/oauth/v2/token";
        String redirectUrl = ServletUriComponentsBuilder.fromCurrentContextPath()
                .build().toUriString() + "/auth/token";
        HttpHeaders headers = new HttpHeaders();
        MultiValueMap<String, Object> map = new LinkedMultiValueMap<>();
        map.add("code", code);
        map.add("grant_type", "authorization_code");
        map.add("client_id", clientId);
        map.add("code_verifier", CODE_CHALLENGE_MAP.get("code_verifier"));
        map.add("redirect_uri", redirectUrl);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, Object>> param = new HttpEntity<>(map, headers);
        ResponseEntity<TokenResponse> response =
                restTemplate.postForEntity(tokenUrl, param, TokenResponse.class);
        return response.getBody();
    }


    public CurrentUserInfo getCurrentUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (Objects.isNull(authentication)) {
            return null;
        }
        Map<String, Object> claimsMap = new HashMap<>();
        if (StringUtils.endsWithIgnoreCase("jwt", authType)) {
            claimsMap = ((JwtAuthenticationToken) authentication).getTokenAttributes();
        } else {
            claimsMap = ((BearerTokenAuthentication) authentication).getTokenAttributes();
        }

        if (Objects.nonNull(claimsMap) && !claimsMap.isEmpty()) {
            CurrentUserInfo currentUserInfo = new CurrentUserInfo();
            if (claimsMap.containsKey(USER_ID_KEY)) {
                currentUserInfo.setUserId(String.valueOf(claimsMap.get(USER_ID_KEY)));
            }

            if (claimsMap.containsKey(USER_NAME_KEY)) {
                currentUserInfo.setUserName(String.valueOf(claimsMap.get(USER_NAME_KEY)));
            }

            List<String> roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority).toList();
            currentUserInfo.setRoles(roles);

            if (claimsMap.containsKey(METADATA_KEY)) {
                LinkedTreeMap<String, String> metadataMap =
                        (LinkedTreeMap<String, String>) claimsMap.get(METADATA_KEY);
                if (Objects.nonNull(metadataMap) && !metadataMap.isEmpty()) {
                    Map<String, String> userMetadata = new HashMap<>();
                    for (String key : metadataMap.keySet()) {
                        String value = new String(
                                java.util.Base64.getDecoder().decode(metadataMap.get(key)),
                                StandardCharsets.UTF_8);
                        userMetadata.put(key, value);
                    }
                    currentUserInfo.setMetadata(userMetadata);
                }
            }
            return currentUserInfo;
        }

        return null;
    }

}
