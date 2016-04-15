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
import com.aerospike.client.Record;
import com.hystrix.configurator.core.BaseCommand;
import io.jwt.primer.aeroapike.AerospikeConnectionManager;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.config.JwtConfig;
import io.jwt.primer.exception.PrimerException;
import io.jwt.primer.model.GetTokenResponse;
import io.jwt.primer.model.ServiceUser;
import io.jwt.primer.model.VerifyResponse;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

import javax.ws.rs.core.Response;
import java.sql.Date;
import java.time.Instant;

/**
 * @author phaneesh
 */
@Slf4j
public class GetTokenCommand extends BaseCommand<GetTokenResponse> {

    private final AerospikeConfig aerospikeConfig;

    private final String id;

    private final String app;

    @Builder
    public GetTokenCommand(final AerospikeConfig aerospikeConfig, final String app, final String id) {
        super("get");
        this.aerospikeConfig = aerospikeConfig;
        this.id = id;
        this.app = app;
    }

    @Override
    protected GetTokenResponse run() throws PrimerException {
        final Key key = new Key(aerospikeConfig.getNamespace(), String.format("%s_tokens", app), id);
        final Record record = AerospikeConnectionManager.getClient().get(null, key);
        if (null == record) {
            throw new PrimerException(Response.Status.NOT_FOUND.getStatusCode(), "PR001", "Not Found");
        }
        return GetTokenResponse.builder()
                .subject(record.getString("subject"))
                .enabled(record.getBoolean("enabled"))
                .expiresAt(Date.from(Instant.ofEpochSecond(record.getLong("expires_at"))))
                .id(id)
                .token(record.getString("token"))
                .issuedAt(Date.from(Instant.ofEpochSecond(record.getLong("issued_at"))))
                .name(record.getString("name"))
                .refreshToken(record.getString("refresh_token"))
                .role(record.getString("role"))
                .build();
    }
}
