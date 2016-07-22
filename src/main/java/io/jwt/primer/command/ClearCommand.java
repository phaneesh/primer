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
import com.hystrix.configurator.core.BaseCommand;
import io.jwt.primer.aeroapike.AerospikeConnectionManager;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.exception.PrimerException;
import io.jwt.primer.model.TokenClearResponse;
import io.jwt.primer.model.TokenDisableResponse;

import javax.ws.rs.core.Response;

/**
 * @author phaneesh
 */
public class ClearCommand extends BaseCommand<TokenClearResponse> {

    private final AerospikeConfig aerospikeConfig;

    private final String app;

    private final String id;

    public ClearCommand(final AerospikeConfig aerospikeConfig, final String app, final String id) {
        super("clear");
        this.aerospikeConfig = aerospikeConfig;
        this.app = app;
        this.id = id;
    }

    @Override
    protected TokenClearResponse run() throws PrimerException {
        final Key key = new Key(aerospikeConfig.getNamespace(), String.format("%s_tokens", app), id);
        final boolean result = AerospikeConnectionManager.getClient().delete(null, key);
        if (!result) {
            throw new PrimerException(Response.Status.NOT_FOUND.getStatusCode(), "PR001", "Not Found");
        }
        return TokenClearResponse.builder().userId(id).build();
    }
}