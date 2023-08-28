/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Huawei Inc.
 *
 */

package demo.app.config;

/**
 * Constants for Zitadel Oauth2 Authorization
 */
public class ZitadelOauth2Constant {

    /**
     * Key for getting login account of user.
     */
    public static final String LOGIN_ACCOUNT_KEY = "preferred_username";

    /**
     * Key for getting name of user.
     */
    public static final String USERNAME_KEY = "name";

    /**
     * Key for getting phone of user.
     */
    public static final String PHONE_KEY = "phone";

    /**
     * Key for getting email of user.
     */
    public static final String EMAIL_KEY = "email";

    /**
     * Key for getting address of user.
     */
    public static final String ADDRESS_KEY = "address";

    /**
     * Key for getting granted roles of user.
     */
    public static final String GRANTED_ROLES_KEY = "urn:zitadel:iam:org:project:roles";

    /**
     * Key for getting metadata of user.
     */
    public static final String METADATA_KEY = "urn:zitadel:iam:user:metadata";

    /**
     * Key for getting id of user.
     */
    public static final String USERID_KEY = "sub";

    /**
     * Auth token type: JWT.
     */
    public static final String AUTH_TYPE_JWT = "JWT";

    /**
     * Auth token type: OpaqueToken.
     */
    public static final String AUTH_TYPE_TOKEN = "OpaqueToken";

    /**
     * Default role granted to user without any roles.
     */
    public static final String DEFAULT_ROLE = "user";

}
