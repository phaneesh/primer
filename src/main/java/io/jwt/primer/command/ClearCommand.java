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
import com.github.rholder.retry.Retryer;
import com.github.rholder.retry.RetryerBuilder;
import com.github.rholder.retry.StopStrategies;
import com.hystrix.configurator.core.BaseCommand;
import io.jwt.primer.aeroapike.AerospikeConnectionManager;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.exception.PrimerException;
import io.jwt.primer.model.TokenClearResponse;

import java.util.concurrent.Callable;

/**
 * @author phaneesh
 */
public class ClearCommand extends BaseCommand<TokenClearResponse> {

    private final AerospikeConfig aerospikeConfig;

    private final String app;

    private final String id;

    private final Retryer<TokenClearResponse> tokenRetryer = RetryerBuilder.<TokenClearResponse>newBuilder()
            .retryIfExceptionOfType(RuntimeException.class)
            .withStopStrategy(StopStrategies.stopAfterAttempt(3))
            .build();

    public ClearCommand(final AerospikeConfig aerospikeConfig, final String app, final String id) {
        super("clear");
        this.aerospikeConfig = aerospikeConfig;
        this.app = app;
        this.id = id;
    }

    @Override
    protected TokenClearResponse run() throws PrimerException {
        Callable<TokenClearResponse> callable = () -> {
            final Key key = new Key(aerospikeConfig.getNamespace(), String.format("%s_tokens", app), id);
            final boolean result = AerospikeConnectionManager.getClient().delete(null, key);
            return result ? TokenClearResponse.builder().userId(id).build() : null;
        };
        try {
            return tokenRetryer.call(callable);
        } catch (Exception e) {
            throw new PrimerException(500, "PR000", e.getMessage());
        }
    }
}
