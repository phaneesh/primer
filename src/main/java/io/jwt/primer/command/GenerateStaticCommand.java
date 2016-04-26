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
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.hystrix.configurator.core.BaseCommand;
import io.jwt.primer.aeroapike.AerospikeConnectionManager;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.config.JwtConfig;
import io.jwt.primer.model.ServiceUser;
import io.jwt.primer.model.StaticTokenResponse;
import io.jwt.primer.model.TokenResponse;
import io.jwt.primer.util.TokenUtil;

/**
 * @author phaneesh
 */
public class GenerateStaticCommand extends BaseCommand<StaticTokenResponse> {

    private final HmacSHA512Signer signer;

    private final AerospikeConfig aerospikeConfig;

    private final String id;

    private final String app;

    private final String role;

    public GenerateStaticCommand(final HmacSHA512Signer signer,
                           final AerospikeConfig aerospikeConfig,
                           final String id, final String app, final String role) {
        super("generate_static");
        this.signer = signer;
        this.aerospikeConfig = aerospikeConfig;
        this.id = id;
        this.app = app;
        this.role = role;
    }

    @Override
    protected StaticTokenResponse run()  {
        final JsonWebToken token = TokenUtil.token(app, id, role);
        final String signedToken = signer.sign(token);
        final Key key = new Key(aerospikeConfig.getNamespace(), String.format("%s_static_tokens", app), id);
        final Bin subjectBin = new Bin("subject", id);
        final Bin roleBin = new Bin("role", role);
        final Bin tokenBin = new Bin("token", signedToken);
        final Bin issuedAtBin = new Bin("issued_at", token.claim().issuedAt());
        final Bin expiresAtBin = new Bin("expires_at", token.claim().expiration());
        final Bin enabledBin = new Bin("enabled", true);
        AerospikeConnectionManager.getClient().put(null, key, subjectBin, roleBin, tokenBin, issuedAtBin,
                expiresAtBin, enabledBin);
        return StaticTokenResponse.builder()
                .token(signedToken)
                .build();
    }
}
