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

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.test.categories.Unit;

/**
 * Unit test for OidcPluginExceptionTest.
 */
@Category({ Unit.class })
public class OidcPluginExceptionTest {

    /**
     * Testing whether you can create specified type of exception.
     */
    @Test
    public void testingForCreatingSpecifiedException() {
        AuthPluginException e = OidcPluginException.INVALID_KEY.create("testMessage");
        assertEquals("OpenID Connect Invalid Key. (testMessage)", e.getMessage());
    }
}
