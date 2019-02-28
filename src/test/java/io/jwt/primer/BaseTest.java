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

package io.jwt.primer;

import com.codahale.metrics.health.HealthCheckRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.srini156.aerospike.client.MockAerospikeClient;
import com.hystrix.configurator.config.HystrixCommandConfig;
import com.hystrix.configurator.config.HystrixConfig;
import com.hystrix.configurator.config.ThreadPoolConfig;
import com.hystrix.configurator.core.HystrixConfigurationFactory;
import io.dropwizard.Configuration;
import io.dropwizard.jersey.DropwizardResourceConfig;
import io.dropwizard.jersey.setup.JerseyEnvironment;
import io.dropwizard.jetty.MutableServletContextHandler;
import io.dropwizard.lifecycle.setup.LifecycleEnvironment;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.jwt.primer.aeroapike.AerospikeConnectionManager;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.config.JwtConfig;
import io.jwt.primer.resource.StaticTokenResource;
import io.jwt.primer.resource.TokenResource;
import org.zapodot.hystrix.bundle.HystrixBundle;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author phaneesh
 */
public class BaseTest {

    private static class PrimerAppTestConfiguration extends Configuration {

        private AerospikeConfig aerospikeConfig = AerospikeConfig.builder()
                .hosts("localhost:3999")
                .maxConnectionsPerNode(2)
                .namespace("test")
                .retries(2)
                .timeout(1000)
                .sleepBetweenRetries(100)
                .build();

        private HystrixConfig hystrix = HystrixConfig.builder()
                .command(HystrixCommandConfig.builder()
                        .name("Dynamic.Generate")
                        .threadPool(ThreadPoolConfig.builder()
                                .concurrency(4)
                                .timeout(1000)
                                .build())
                        .build())
                .command(HystrixCommandConfig.builder()
                        .name("Static.Generate")
                        .threadPool(ThreadPoolConfig.builder()
                                .concurrency(4)
                                .timeout(1000)
                                .build())
                        .build())
                .command(HystrixCommandConfig.builder()
                        .name("Dynamic.Get")
                        .threadPool(ThreadPoolConfig.builder()
                                .concurrency(4)
                                .timeout(1000)
                                .build())
                        .build())
                .command(HystrixCommandConfig.builder()
                        .name("Static.Get")
                        .threadPool(ThreadPoolConfig.builder()
                                .concurrency(4)
                                .timeout(1000)
                                .build())
                        .build())
                .command(HystrixCommandConfig.builder()
                        .name("Dynamic.Refresh")
                        .threadPool(ThreadPoolConfig.builder()
                                .concurrency(4)
                                .timeout(1000)
                                .build())
                        .build())
                .command(HystrixCommandConfig.builder()
                        .name("Dynamic.Disable")
                        .threadPool(ThreadPoolConfig.builder()
                                .concurrency(4)
                                .timeout(1000)
                                .build())
                        .build())
                .command(HystrixCommandConfig.builder()
                        .name("Static.Disable")
                        .threadPool(ThreadPoolConfig.builder()
                                .concurrency(4)
                                .timeout(1000)
                                .build())
                        .build())
                .build();

        private JwtConfig jwtConfig = JwtConfig.builder()
                .clockSkew(60)
                .expiry(10)
                .privateKey("testisatesttestisatesttestisatesttestisatesttestisatest")
                .build();

        private String staticPrivateKey = "testisatesttestisatesttestisatesttestisatesttestisatest";
    }

    protected final static HealthCheckRegistry healthChecks = mock(HealthCheckRegistry.class);
    protected final static JerseyEnvironment jerseyEnvironment = mock(JerseyEnvironment.class);
    protected final static LifecycleEnvironment lifecycleEnvironment = new LifecycleEnvironment();
    protected static final Environment environment = mock(Environment.class);
    protected final static Bootstrap<PrimerConfiguration> bootstrap = mock(Bootstrap.class);

    private static final PrimerAppTestConfiguration config = new PrimerAppTestConfiguration();

    protected static TokenResource tokenResource;

    protected static StaticTokenResource staticTokenResource;

    private static HystrixBundle hystrixBundle = HystrixBundle.builder().disableMetricsPublisher().disableStreamServletInAdminContext().build();

    static {
        when(jerseyEnvironment.getResourceConfig()).thenReturn(new DropwizardResourceConfig());
        when(environment.jersey()).thenReturn(jerseyEnvironment);
        when(environment.lifecycle()).thenReturn(lifecycleEnvironment);
        when(environment.healthChecks()).thenReturn(healthChecks);
        when(environment.getObjectMapper()).thenReturn(new ObjectMapper());
        when(bootstrap.getObjectMapper()).thenReturn(new ObjectMapper());
        when(environment.getApplicationContext()).thenReturn(new MutableServletContextHandler());
        when(environment.getAdminContext()).thenReturn(new MutableServletContextHandler());

        hystrixBundle.initialize(bootstrap);
        hystrixBundle.run(config, environment);

        HystrixConfigurationFactory.init(config.hystrix);

        MockAerospikeClient aerospikeClient = new MockAerospikeClient();
        AerospikeConnectionManager.setClient(aerospikeClient);

        tokenResource = new TokenResource(config.jwtConfig, config.aerospikeConfig);

        staticTokenResource = new StaticTokenResource(config.staticPrivateKey, config.aerospikeConfig);

    }
}
