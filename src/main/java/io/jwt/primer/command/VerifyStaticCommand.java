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
import io.jwt.primer.exception.PrimerException;
import io.jwt.primer.model.VerifyStaticResponse;

import javax.ws.rs.core.Response;

/**
 * @author phaneesh
 */
public class VerifyStaticCommand extends BaseCommand<VerifyStaticResponse> {

    private final AerospikeConfig aerospikeConfig;

    private final String token;

    private final String id;

    private final String app;

    private final String role;

    public VerifyStaticCommand(final AerospikeConfig aerospikeConfig, final String token,
                         final String id, final String app, final String role) {
        super("verify_static");
        this.aerospikeConfig = aerospikeConfig;
        this.token = token;
        this.id = id;
        this.app = app;
        this.role = role;
    }

    @Override
    protected VerifyStaticResponse run() throws PrimerException {
        final Key key = new Key(aerospikeConfig.getNamespace(), String.format("%s_static_tokens", app), id);
        final Record record = AerospikeConnectionManager.getClient().get(null, key, "token", "subject", "enabled", "role");
        if (null == record) {
            throw new PrimerException(Response.Status.NOT_FOUND.getStatusCode(), "PR001", "Not Found");
        }
        if (!record.getBoolean("enabled")) {
            throw new PrimerException(Response.Status.FORBIDDEN.getStatusCode(), "PR002", "Forbidden");
        }
        final String subject = record.getString("subject");
        final String role = record.getString("role");
        final String fetchedToken = record.getString("token");
        if (token.equals(fetchedToken) && id.equals(subject)
                && role.equals(role)) {
            return VerifyStaticResponse.builder()
                    .token(fetchedToken)
                    .id(subject)
                    .role(role)
                    .build();
        } else {
            throw new PrimerException(Response.Status.UNAUTHORIZED.getStatusCode(), "PR004", "Unauthorized");
        }
    }
}