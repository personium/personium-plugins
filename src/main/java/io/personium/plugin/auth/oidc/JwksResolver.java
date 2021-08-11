/**
 * Personium
 * Copyright 2014-2021 Personium Project Authors
 * - FUJITSU LIMITED
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.personium.plugin.auth.oidc;

import java.security.Key;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.personium.plugin.base.auth.AuthPluginException;

/**
 * Resolver of json web key for io.jsonwebtoken.JwtParser.
 */
public class JwksResolver extends SigningKeyResolverAdapter {

    /** json web keys. */
    private Jwks jwks;

    /**
     * Constructor of JwksResolver.
     * @param jwks Jwks object containing json web key.
     */
    public JwksResolver(Jwks jwks) {
        this.jwks = jwks;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @SuppressWarnings("rawtypes")
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        String kid = header.getKeyId();
        String alg = header.getAlgorithm();
        try {
            Key pubKey = jwks.getKey(kid, alg);
            return pubKey;
        } catch (AuthPluginException e) {
            return null;
        }
    }
}
