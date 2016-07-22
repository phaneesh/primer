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

package io.jwt.primer.command;

import com.aerospike.client.Bin;
import com.aerospike.client.Key;
import com.aerospike.client.Operation;
import com.aerospike.client.Record;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.hystrix.configurator.core.BaseCommand;
import io.jwt.primer.aeroapike.AerospikeConnectionManager;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.config.JwtConfig;
import io.jwt.primer.exception.PrimerException;
import io.jwt.primer.model.DynamicToken;
import io.jwt.primer.model.RefreshResponse;
import io.jwt.primer.model.ServiceUser;
import io.jwt.primer.util.TokenUtil;

import javax.ws.rs.core.Response;

/**
 * @author phaneesh
 */
public class RefreshCommand extends BaseCommand<RefreshResponse> {

    private final HmacSHA512Signer signer;

    private final JwtConfig jwtConfig;

    private final AerospikeConfig aerospikeConfig;

    private final String id;

    private final String app;

    private DynamicToken token;

    public RefreshCommand(final HmacSHA512Signer signer, final JwtConfig jwtConfig,
                          final AerospikeConfig aerospikeConfig,
                          final String id, final String app, final DynamicToken token) {
        super("refresh");
        this.signer = signer;
        this.jwtConfig = jwtConfig;
        this.aerospikeConfig = aerospikeConfig;
        this.id = id;
        this.app = app;
        this.token = token;
    }

    @Override
    protected RefreshResponse run() throws PrimerException {
        final Key key = new Key(aerospikeConfig.getNamespace(), String.format("%s_tokens", app), id);
        final ServiceUser serviceUser = ServiceUser.builder()
                .id(token.getSubject())
                .role(token.getRole())
                .name(token.getName())
                .build();
        final JsonWebToken newToken = TokenUtil.token(app, id, serviceUser, jwtConfig);
        final String newRefreshToken = TokenUtil.refreshToken(app, id, jwtConfig, newToken);
        final String newSignedToken = signer.sign(newToken);
        final Bin tokenBin = new Bin("token", newSignedToken);
        final Bin refreshTokenBin = new Bin("refresh_token", newRefreshToken);
        final Bin issuedAtBin = new Bin("issued_at", newToken.claim().issuedAt());
        final Bin expiresAtBin = new Bin("expires_at", newToken.claim().expiration());
        final Bin previousRefreshToken = new Bin("refresh_token_prev", token.getRefreshToken());
        AerospikeConnectionManager.getClient().operate(null, key,
                Operation.put(tokenBin),
                Operation.put(refreshTokenBin),
                Operation.put(previousRefreshToken),
                Operation.put(issuedAtBin),
                Operation.put(expiresAtBin));
        return RefreshResponse.builder()
                .token(newSignedToken)
                .refreshToken(newRefreshToken)
                .expiresAt(newToken.claim().expiration())
                .build();
    }
}
