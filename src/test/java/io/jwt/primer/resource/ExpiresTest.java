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

import org.junit.Assert;
import org.junit.Test;

import java.time.Instant;

/**
 * @author phaneesh
 */
public class ExpiresTest {


    @Test
    public void testExpity() {
        long adjusted = Instant.ofEpochMilli(1469012219).plusSeconds(60).getEpochSecond();
        long now = Instant.now().getEpochSecond();
        Assert.assertTrue(adjusted < now);

    }
}
