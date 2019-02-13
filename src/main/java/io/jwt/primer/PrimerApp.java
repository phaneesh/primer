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

import com.codahale.metrics.health.HealthCheck;
import com.hystrix.configurator.core.HystrixConfigurationFactory;
import io.dropwizard.Application;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.discovery.bundle.ServiceDiscoveryBundle;
import io.dropwizard.discovery.bundle.ServiceDiscoveryConfiguration;
import io.dropwizard.lifecycle.Managed;
import io.dropwizard.oor.OorBundle;
import io.dropwizard.riemann.RiemannBundle;
import io.dropwizard.riemann.RiemannConfig;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.federecio.dropwizard.swagger.SwaggerBundle;
import io.federecio.dropwizard.swagger.SwaggerBundleConfiguration;
import io.jwt.primer.aeroapike.AerospikeConnectionManager;
import io.jwt.primer.exception.PrimerExceptionMapper;
import io.jwt.primer.resource.CustomTokenResource;
import io.jwt.primer.resource.StaticTokenResource;
import io.jwt.primer.resource.TokenResource;
import io.jwt.primer.tasks.DeleteDynamicTokensTask;
import io.jwt.primer.tasks.DeleteStaticTokensTask;
import org.zapodot.hystrix.bundle.HystrixBundle;

/**
 * @author phaneesh
 */
public class PrimerApp extends Application<PrimerConfiguration> {

    private static ServiceDiscoveryBundle<PrimerConfiguration> serviceDiscoveryBundle;

    public static void main(String[] args) throws Exception {
        PrimerApp primerApp = new PrimerApp();
        primerApp.run(args);
    }

    @Override
    public void initialize(final Bootstrap<PrimerConfiguration> bootstrap) {
        bootstrap.setConfigurationSourceProvider(
                new SubstitutingSourceProvider(bootstrap.getConfigurationSourceProvider(),
                        new EnvironmentVariableSubstitutor()
                )
        );
        bootstrap.addBundle(HystrixBundle.builder()
                .disableStreamServletInAdminContext()
                .withApplicationStreamPath("/hystrix.stream").build());
        bootstrap.addBundle(new SwaggerBundle<PrimerConfiguration>() {
            @Override
            protected SwaggerBundleConfiguration getSwaggerBundleConfiguration(PrimerConfiguration configuration) {
                return configuration.getSwagger();
            }
        });
        serviceDiscoveryBundle = new ServiceDiscoveryBundle<PrimerConfiguration>() {
            @Override
            protected ServiceDiscoveryConfiguration getRangerConfiguration(PrimerConfiguration configuration) {
                return configuration.getDiscovery();
            }

            @Override
            protected String getServiceName(PrimerConfiguration configuration) {
                return "primer";
            }

            @Override
            protected int getPort(PrimerConfiguration configuration) {
                return Integer.parseInt(System.getenv("PORT_8080"));
            }

            protected String getHost() {
                return System.getenv("HOST");
            }
        };
        bootstrap.addBundle(serviceDiscoveryBundle);
        bootstrap.addBundle(new RiemannBundle<PrimerConfiguration>() {
            @Override
            public RiemannConfig getRiemannConfiguration(PrimerConfiguration apiConfiguration) {
                return apiConfiguration.getRiemann();
            }
        });
        bootstrap.addBundle(new OorBundle<PrimerConfiguration>() {
            @Override
            public boolean withOor() {
                return false;
            }
        });
    }

    @Override
    public void run(PrimerConfiguration configuration, Environment environment) throws Exception {
        HystrixConfigurationFactory.init(configuration.getHystrix());
        environment.lifecycle().manage(new Managed() {
            @Override
            public void start() throws Exception {
                AerospikeConnectionManager.init(configuration.getAerospike());
            }

            @Override
            public void stop() throws Exception {
                AerospikeConnectionManager.close();
            }
        });
        environment.healthChecks().register("aerospike", new HealthCheck() {
            @Override
            protected Result check() throws Exception {
                return AerospikeConnectionManager.getClient().isConnected() ?
                        HealthCheck.Result.healthy() : HealthCheck.Result.unhealthy("Aerospike connection error");
            }
        });
        environment.jersey().register(new TokenResource(configuration.getJwt(), configuration.getAerospike()));
        environment.jersey().register(new CustomTokenResource(configuration.getJwt(), configuration.getAerospike()));
        environment.jersey().register(new StaticTokenResource(configuration.getJwt().getPrivateKey(), configuration.getAerospike()));
        environment.admin().addTask(new DeleteDynamicTokensTask(configuration.getAerospike()));
        environment.admin().addTask(new DeleteStaticTokensTask(configuration.getAerospike()));
        environment.jersey().register( new PrimerExceptionMapper());
    }
}
