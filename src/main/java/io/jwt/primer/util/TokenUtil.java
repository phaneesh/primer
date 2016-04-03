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

package io.jwt.primer.util;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import io.jwt.primer.config.JwtConfig;
import lombok.val;
import org.joda.time.DateTime;

/**
 * @author phaneesh
 */
public class TokenUtil {

    public static JsonWebToken token(final String app, final String id, final String role, final String name,
                                     final JwtConfig jwtConfig) {
        return JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(
                        JsonWebTokenClaim.builder()
                                .issuedAt(DateTime.now())
                                .issuer(app)
                                .subject(id)
                                .expiration(DateTime.now().plusSeconds(jwtConfig.getExpiry()))
                                .param("role" , role)
                                .param("name", name)
                                .build()
                ).build();
    }

    public static String refreshToken(final String app, final String id, final JwtConfig jwtConfig,
                                      final JsonWebToken token) {
        val hasher = Hashing.murmur3_128().newHasher();
        hasher.putString(app, Charsets.UTF_8);
        hasher.putString(id, Charsets.UTF_8);
        hasher.putLong(token.claim().expiration());
        hasher.putString(jwtConfig.getPrivateKey(), Charsets.UTF_8);
        return hasher.hash().toString();
    }
}
