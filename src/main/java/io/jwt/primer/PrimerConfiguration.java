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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.hystrix.configurator.config.HystrixConfig;
import io.dropwizard.Configuration;
import io.dropwizard.discovery.bundle.ServiceDiscoveryConfiguration;
import io.federecio.dropwizard.swagger.SwaggerBundleConfiguration;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.config.JwtConfig;
import lombok.*;

/**
 * @author phaneesh
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PrimerConfiguration extends Configuration {

    private AerospikeConfig aerospike;

    private SwaggerBundleConfiguration swagger;

    @JsonProperty("hystrix")
    @Getter
    @Setter
    private HystrixConfig hystrixConfig;

    @JsonProperty("jwt")
    @Getter
    @Setter
    private JwtConfig jwtConfig;

    @JsonProperty("discovery")
    @Getter
    @Setter
    private ServiceDiscoveryConfiguration serviceDiscoveryConfiguration;

}
