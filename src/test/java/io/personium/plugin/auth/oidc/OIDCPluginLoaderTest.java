/**
 * Personium
 * Copyright 2021 Personium Project Authors
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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import io.personium.plugin.base.auth.AuthPlugin;
import io.personium.plugin.base.auth.AuthPluginLoader;
import io.personium.test.categories.Unit;

/**
 * Unit test for OIDCPluginLoaderTest.
 */
@Category({Unit.class})
public class OIDCPluginLoaderTest extends OIDCTestBase {

    /**
     * Test if OIDCPluginLoader can load only plugins which is enabled.
     */
    @Test
    public void multipleInstanceLoadingTest() {

        String keyConfigurationFile = "io.personium.configurationFile";

        String prevConfig = System.getProperty(keyConfigurationFile);
        System.setProperty(keyConfigurationFile, "personium-unit-config-oidcpluginloadertest.properties");

        try {
            OIDCPluginLoader loader = new OIDCPluginLoader();
            if (!(loader instanceof AuthPluginLoader)) {
                fail("PluginLoader must implement AuthPluginLoader");
            }
            List<AuthPlugin> arrPlugin = loader.loadInstances();

            Set<String> accountTypes = new HashSet<String>(
                    Arrays.asList("accountType001", "accountType002", "accountType004"));

            assertEquals(3, arrPlugin.size());

            Set<String> authPluginTypes = new HashSet<String>();
            for (AuthPlugin authPlugin : arrPlugin) {
                authPluginTypes.add(authPlugin.getAccountType());
            }
            assertTrue(authPluginTypes.containsAll(accountTypes));
        } finally {
            if (prevConfig == null) {
                System.clearProperty(keyConfigurationFile);
            } else {
                System.setProperty(keyConfigurationFile, prevConfig);
            }
        }
    }

}
