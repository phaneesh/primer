/*
 * Copyright 2016 Phaneesh Nagaraja <phaneesh.n@gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.jwt.primer.resource;

import io.dropwizard.testing.junit.ResourceTestRule;
import io.jwt.primer.BaseTest;
import io.jwt.primer.model.StaticTokenResponse;
import io.jwt.primer.model.VerifyStaticResponse;
import org.junit.ClassRule;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

/**
 * @author phaneesh
 */
public class StaticTokenResourceTest extends BaseTest {

    @ClassRule
    public static ResourceTestRule resources = ResourceTestRule.builder()
            .addResource(staticTokenResource)
            .build();

    @Test
    public void testGenerateToken() {
        StaticTokenResponse result = resources.client().target("/v1/generate/static/test/test/test").request()
                .post(null, StaticTokenResponse.class);
        assertNotNull(result.getToken());
    }

    @Test
    public void testVerifyToken() {
        StaticTokenResponse result = resources.client().target("/v1/generate/static/test/test/test").request()
                .post(null, StaticTokenResponse.class);
        assertNotNull(result.getToken());
        VerifyStaticResponse verifyResponse = resources.client().target("/v1/verify/static/test/test/test").request()
                .header("X-Auth-Token", result.getToken())
                .post(null, VerifyStaticResponse.class);
        assertNotNull(verifyResponse.getToken());
    }
}
