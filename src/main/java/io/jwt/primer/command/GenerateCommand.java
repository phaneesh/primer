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
import com.github.rholder.retry.Retryer;
import com.github.rholder.retry.RetryerBuilder;
import com.github.rholder.retry.StopStrategies;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.hystrix.configurator.core.BaseCommand;
import io.jwt.primer.aeroapike.AerospikeConnectionManager;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.config.JwtConfig;
import io.jwt.primer.exception.PrimerException;
import io.jwt.primer.model.ServiceUser;
import io.jwt.primer.model.TokenResponse;
import io.jwt.primer.util.TokenUtil;

import java.util.concurrent.Callable;

/**
 * @author phaneesh
 */
public class GenerateCommand extends BaseCommand<TokenResponse> {

    private final HmacSHA512Signer signer;

    private final JwtConfig jwtConfig;

    private final AerospikeConfig aerospikeConfig;

    private final String id;

    private final String app;

    private final ServiceUser user;

    private final Retryer<TokenResponse> tokenRetryer = RetryerBuilder.<TokenResponse>newBuilder()
            .retryIfExceptionOfType(RuntimeException.class)
            .withStopStrategy(StopStrategies.stopAfterAttempt(3))
            .build();


    public GenerateCommand(final HmacSHA512Signer signer, final JwtConfig jwtConfig,
                           final AerospikeConfig aerospikeConfig,
                           final String id, final String app, final ServiceUser user) {
        super("generate");
        this.signer = signer;
        this.jwtConfig = jwtConfig;
        this.aerospikeConfig = aerospikeConfig;
        this.id = id;
        this.app = app;
        this.user = user;
    }

    @Override
    protected TokenResponse run() throws PrimerException {
        Callable<TokenResponse> callable = () -> {
            final JsonWebToken token = TokenUtil.token(app, id, user, jwtConfig);
            final String signedToken = signer.sign(token);
            final String refreshToken = TokenUtil.refreshToken(app, id, jwtConfig, token);
            final Key key = new Key(aerospikeConfig.getNamespace(), String.format("%s_tokens", app), id);
            final Bin subjectBin = new Bin("subject", user.getId());
            final Bin roleBin = new Bin("role", user.getRole());
            final Bin nameBin = new Bin("name", user.getName());
            final Bin tokenBin = new Bin("token", signedToken);
            final Bin refreshTokenBin = new Bin("refresh_token", refreshToken);
            final Bin issuedAtBin = new Bin("issued_at", token.claim().issuedAt());
            final Bin expiresAtBin = new Bin("expires_at", token.claim().expiration());
            final Bin enabledBin = new Bin("enabled", true);
            AerospikeConnectionManager.getClient().put(null, key, subjectBin, roleBin, nameBin, tokenBin, refreshTokenBin,
                    issuedAtBin, expiresAtBin, enabledBin);
            return TokenResponse.builder()
                    .token(signedToken)
                    .refreshToken(refreshToken)
                    .expiresAt(token.claim().expiration())
                    .build();
        };
        try {
            return tokenRetryer.call(callable);
        } catch(Exception e) {
            throw new PrimerException(500, "PR000", e.getMessage());
        }
    }
}
