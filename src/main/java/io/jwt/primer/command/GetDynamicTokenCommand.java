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
import com.github.rholder.retry.Retryer;
import com.github.rholder.retry.RetryerBuilder;
import com.github.rholder.retry.StopStrategies;
import com.hystrix.configurator.core.BaseCommand;
import io.jwt.primer.aeroapike.AerospikeConnectionManager;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.exception.PrimerException;
import io.jwt.primer.model.DynamicToken;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

import java.sql.Date;
import java.time.Instant;
import java.util.concurrent.Callable;

/**
 * @author phaneesh
 */
@Slf4j
public class GetDynamicTokenCommand extends BaseCommand<DynamicToken> {

    private final AerospikeConfig aerospikeConfig;

    private final Retryer<DynamicToken> tokenRetryer = RetryerBuilder.<DynamicToken>newBuilder()
            .retryIfExceptionOfType(RuntimeException.class)
            .withStopStrategy(StopStrategies.stopAfterAttempt(3))
            .build();

    private final String id;

    private final String app;

    @Builder
    public GetDynamicTokenCommand(final AerospikeConfig aerospikeConfig, final String app, final String id) {
        super("get_dynamic");
        this.aerospikeConfig = aerospikeConfig;
        this.id = id;
        this.app = app;
    }

    @Override
    protected DynamicToken run() throws PrimerException {
        Callable<DynamicToken> callable = () -> {
            final Key key = new Key(aerospikeConfig.getNamespace(), String.format("%s_tokens", app), id);
            final Record record = AerospikeConnectionManager.getClient().get(null, key);
            if (null == record) {
                return null;
            }
            return DynamicToken.builder()
                    .subject(record.getString("subject"))
                    .enabled(record.getBoolean("enabled"))
                    .expiresAt(Date.from(Instant.ofEpochSecond(record.getLong("expires_at"))))
                    .id(id)
                    .token(record.getString("token"))
                    .previousToken(record.getString("tokenp"))
                    .issuedAt(Date.from(Instant.ofEpochSecond(record.getLong("issued_at"))))
                    .name(record.getString("name"))
                    .refreshToken(record.getString("refresh_token"))
                    .previousRefreshToken(record.getString("refresh_tokenp"))
                    .role(record.getString("role"))
                    .build();
        };
        try {
            return tokenRetryer.call(callable);
        } catch (Exception e) {
            throw new PrimerException(500, "PR000", e.getMessage());
        }
    }
}
