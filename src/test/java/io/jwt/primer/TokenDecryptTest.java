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

package io.jwt.primer;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * @author phaneesh
 */
public class TokenDecryptTest {

    @Test
    public void testDecrypt() {
        String key = "TwhjV5ujkvb41frpmqCve7ZfhqwSDMqOXe01DeDIsb2xCrW4bwfFnax9bi2uC9Kn";
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJwaG9uZXBlLWNvbnN1bWVyLWFwcCIsImV4cCI6MTQ4OTk4NzA1OSwiaWF0IjoxNDg5OTgzNDU5LCJzdWIiOiJiOGRlMTBkNWUzN2Y0MjAxYlhOdE9Ea3pOdy1jV052YlEtT0Rsa00yUmhZakUzWkRVejpVMTcwMzE0MTgxODAyMTgxMTAyMzYzNzpkMzdlNWVhODA1YTE0MTg3YWI3OTYxNDViNjcwM2VlMiIsInJvbGUiOiJjb25zdW1lciIsInVzZXJfaWQiOiJVMTcwMzE0MTgxODAyMTgxMTAyMzYzNyIsIm5hbWUiOiJVMTcwMzE0MTgxODAyMTgxMTAyMzYzNyIsInR5cGUiOiJkeW5hbWljIn0.a8H8_ETy4cEFzY_7J2T2KhGjxeYAxyqbX0EpM3BTRakDd8td20MAhQ2TZtatV2q-EtGzDWy91NTUCniXLWxVsA";

        final JsonWebTokenParser tokenParser = new DefaultJsonWebTokenParser();
        final byte[] secretKey = key.getBytes(StandardCharsets.UTF_8);
        final HmacSHA512Verifier tokenVerifier = new HmacSHA512Verifier(secretKey);

        final JsonWebToken webToken = tokenParser.parse(token);

        System.out.println(webToken.header().algorithm());


    }
}
