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
import com.github.rholder.retry.RetryException;
import com.github.rholder.retry.Retryer;
import com.github.rholder.retry.RetryerBuilder;
import com.github.rholder.retry.StopStrategies;
import com.hystrix.configurator.core.BaseCommand;
import io.jwt.primer.aeroapike.AerospikeConnectionManager;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.exception.PrimerException;
import io.jwt.primer.model.StaticToken;

import java.io.EOFException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

/**
 * @author phaneesh
 */
public class GetStaticTokenCommand extends BaseCommand<StaticToken> {

    private final AerospikeConfig aerospikeConfig;

    private final Retryer<StaticToken> tokenRetryer = RetryerBuilder.<StaticToken>newBuilder()
            .retryIfExceptionOfType(EOFException.class)
            .withStopStrategy(StopStrategies.stopAfterAttempt(3))
            .build();

    private final String id;

    private final String app;

    public GetStaticTokenCommand(final AerospikeConfig aerospikeConfig, final String id, final String app) {
        super("get_static");
        this.aerospikeConfig = aerospikeConfig;
        this.id = id;
        this.app = app;
    }

    @Override
    protected StaticToken run() throws PrimerException {
        Callable<StaticToken> callable = () -> {
            final Key key = new Key(aerospikeConfig.getNamespace(), String.format("%s_static_tokens", app), id);
            final Record record = AerospikeConnectionManager.getClient().get(null, key, "token", "subject", "enabled", "role");
            if (null == record) {
                return null;
            }
            return StaticToken.builder()
                    .id(id)
                    .enabled(record.getBoolean("enabled"))
                    .role(record.getString("role"))
                    .subject(record.getString("subject"))
                    .token(record.getString("token"))
                    .build();
        };
        try {
            return tokenRetryer.call(callable);
        } catch (ExecutionException e) {
            throw new PrimerException(500, "PR000", e.getMessage());
        } catch (RetryException e) {
            throw new PrimerException(500, "PR000", e.getMessage());
        }
    }
}