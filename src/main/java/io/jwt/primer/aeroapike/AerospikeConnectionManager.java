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

package io.jwt.primer.aeroapike;

import com.aerospike.client.AerospikeClient;
import com.aerospike.client.Host;
import com.aerospike.client.IAerospikeClient;
import com.aerospike.client.policy.*;
import com.google.common.base.Preconditions;
import io.jwt.primer.config.AerospikeConfig;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * @author phaneesh
 */
@Slf4j
public class AerospikeConnectionManager {

    private static IAerospikeClient client;

    private static AerospikeConfig config;

    public static void init(AerospikeConfig aerospikeConfig) {
        config = aerospikeConfig;
        val readPolicy = new Policy();
        readPolicy.maxRetries = config.getRetries();
        readPolicy.consistencyLevel = ConsistencyLevel.CONSISTENCY_ONE;
        readPolicy.replica = Replica.RANDOM;
        readPolicy.sleepBetweenRetries = config.getSleepBetweenRetries();
        readPolicy.timeout = config.getTimeout();

        val writePolicy = new WritePolicy();
        writePolicy.maxRetries = config.getRetries();
        writePolicy.consistencyLevel = ConsistencyLevel.CONSISTENCY_ALL;
        writePolicy.replica = Replica.MASTER;
        writePolicy.sleepBetweenRetries = config.getSleepBetweenRetries();
        writePolicy.timeout = config.getTimeout();

        val clientPolicy = new ClientPolicy();
        clientPolicy.maxConnsPerNode = config.getMaxConnectionsPerNode();
        clientPolicy.readPolicyDefault = readPolicy;
        clientPolicy.writePolicyDefault = writePolicy;
        clientPolicy.failIfNotConnected = true;

        val hosts = config.getHosts().split(",");
        val hostAddresses = Arrays.stream(hosts).map( h -> {
            String host[] = h.split(":");
            if(host.length == 2) {
                return new Host(host[0], Integer.parseInt(host[1]));
            } else {
                return new Host(host[0], 3000);
            }
        }).collect(Collectors.toList());
        client = new AerospikeClient(clientPolicy, hostAddresses.toArray(new Host[0]));
        log.info("Aerospike connection status: " +client.isConnected());
    }

    public static IAerospikeClient getClient() {
        Preconditions.checkNotNull(client);
        return client;
    }

    public static void setClient(IAerospikeClient aerospikeClient) {
        client = aerospikeClient;
    }

    public static void close() {
        if(null != client) {
            client.close();
        }
    }

}
