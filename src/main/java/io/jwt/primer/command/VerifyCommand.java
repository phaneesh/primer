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

import com.aerospike.client.Key;
import com.aerospike.client.Record;
import com.hystrix.configurator.core.BaseCommand;
import io.jwt.primer.aeroapike.AerospikeConnectionManager;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.config.JwtConfig;
import io.jwt.primer.exception.PrimerException;
import io.jwt.primer.model.ServiceUser;
import io.jwt.primer.model.VerifyResponse;
import lombok.extern.slf4j.Slf4j;

import javax.ws.rs.core.Response;
import java.time.Instant;

/**
 * @author phaneesh
 */
@Slf4j
public class VerifyCommand extends BaseCommand<VerifyResponse> {

    private final AerospikeConfig aerospikeConfig;

    private final JwtConfig jwtConfig;

    private final String token;

    private final String id;

    private final String app;

    private final ServiceUser user;

    public VerifyCommand(final AerospikeConfig aerospikeConfig, final JwtConfig jwtConfig, final String token,
                         final String id, final String app, final ServiceUser user) {
        super("verify");
        this.aerospikeConfig = aerospikeConfig;
        this.jwtConfig = jwtConfig;
        this.token = token;
        this.id = id;
        this.app = app;
        this.user = user;
    }

    @Override
    protected VerifyResponse run() throws PrimerException {
        final Key key = new Key(aerospikeConfig.getNamespace(), String.format("%s_tokens", app), id);
        final Record record = AerospikeConnectionManager.getClient().get(null, key, "token", "subject", "enabled", "role", "name", "expires_at");
        if (null == record) {
            throw new PrimerException(Response.Status.NOT_FOUND, "PR001", "Not Found");
        }
        if(!record.getBoolean("enabled")) {
            throw new PrimerException(Response.Status.FORBIDDEN, "PR002", "Forbidden");
        }
        final String subject = record.getString("subject");
        final String role = record.getString("role");
        final String name = record.getString("name");
        final String fetchedToken = record.getString("token");
        final long expires_at = record.getLong("expires_at");
        final long adjusted = Instant.ofEpochSecond(expires_at).plusSeconds(jwtConfig.getClockSkew()).getEpochSecond();
        final long now = Instant.now().getEpochSecond();
        log.info("Expires At: {} | Clock Skew: {} | Adjusted: {} | Now: {}",
                expires_at, jwtConfig.getClockSkew(), adjusted, now);
        if(now >= adjusted) {
            throw new PrimerException(Response.Status.PRECONDITION_FAILED, "PR003", "Expired");
        }
        if(token.equals(fetchedToken) && user.getId().equals(subject)
                && user.getName().equals(name) && user.getRole().equals(role)) {
            return VerifyResponse.builder()
                    .expiresAt(expires_at)
                    .token(fetchedToken)
                    .userId(subject)
                    .build();
        } else {
            throw new PrimerException(Response.Status.UNAUTHORIZED, "PR004", "Unauthorized");
        }
    }
}
