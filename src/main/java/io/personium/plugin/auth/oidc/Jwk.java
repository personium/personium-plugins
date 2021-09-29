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

/**
 * JSON Web Key Class. Please refer to https://datatracker.ietf.org/doc/html/rfc7516#section-4.1 .
 */
public final class Jwk {

    /** Key for Key Type Parameter. */
    public static final String KEY_TYPE = "kty";

    /** Key for Public Key Use Parameter. */
    public static final String PUBLIC_KEY_USE = "use";

    /** Key for Key Operations Parameter. */
    public static final String KEY_OPERATIONS = "key_ops";

    /** Key for Algorithm Parameter. */
    public static final String ALGORITHM = "alg";

    /** Key for Key ID Parameter. */
    public static final String KEY_ID = "kid";

    /** Key for X.509 URL Parameter. */
    public static final String X509_URL = "x5u";

    /** Key for X.509 Certificate Chain Parameter. */
    public static final String X509_CERTIFICATE_CHAIN = "x5c";

    /** Key for X.509 Certificate SHA-1 Thumbprint Parameter. */
    public static final String X509_CERTIFICATE_SHA1_THUMBPRINT = "x5t";

    /** Key for X.509 Certificate SHA-256 Thumbprint Parameter. */
    public static final String X509_CERTIFICATE_SHA256_THUMBPRINT = "x5t#256";

    /**
     * This class cannot instanciate.
     */
    private Jwk() {
    }
}
