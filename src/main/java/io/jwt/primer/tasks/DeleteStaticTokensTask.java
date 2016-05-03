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

package io.jwt.primer.tasks;

import com.google.common.collect.ImmutableMultimap;
import io.dropwizard.servlets.tasks.Task;
import io.jwt.primer.aeroapike.AerospikeConnectionManager;
import io.jwt.primer.config.AerospikeConfig;
import lombok.extern.slf4j.Slf4j;

import javax.inject.Singleton;
import java.io.PrintWriter;

/**
 * @author phaneesh
 */
@Singleton
@Slf4j
public class DeleteStaticTokensTask extends Task {

    private final AerospikeConfig aerospikeConfig;

    public DeleteStaticTokensTask(AerospikeConfig aerospikeConfig) {
        super("delete-static-tokens");
        this.aerospikeConfig = aerospikeConfig;
    }

    @Override
    public void execute(ImmutableMultimap<String, String> parameters, PrintWriter out) throws Exception {
        if(parameters.containsKey("app")) {
            log.info("Deleting static tokens for app: " +parameters.get("app").asList().get(0));
            final String setName = parameters.get("app").asList().get(0) + "_static_tokens";
            log.info("Set Name: " +setName);
            AerospikeConnectionManager.getClient().scanAll(null, aerospikeConfig.getNamespace(),
                    setName, (key, record) ->
                            AerospikeConnectionManager.getClient().delete(null, key));
            out.print("Static tokens for app: [" +parameters.get("app").asList().get(0) +"] is being deleted" );
        } else {
            out.print("Parameter[app] missing!" );
        }
    }
}
