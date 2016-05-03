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

import javax.inject.Singleton;
import java.io.PrintWriter;

/**
 * @author phaneesh
 */
@Singleton
public class DeleteStaticTokensTask extends Task {

    private final AerospikeConfig aerospikeConfig;

    public DeleteStaticTokensTask(AerospikeConfig aerospikeConfig) {
        super("delete-static-tokens");
        this.aerospikeConfig = aerospikeConfig;
    }

    @Override
    public void execute(ImmutableMultimap<String, String> parameters, PrintWriter out) throws Exception {
        if(parameters.containsKey("app")) {
            AerospikeConnectionManager.getClient().scanAll(null, aerospikeConfig.getNamespace(),
                    parameters.get("app") + "_static_tokens", (key, record) ->
                            AerospikeConnectionManager.getClient().delete(null, key));
        } else {
            out.print("Static tokens for app: [" +parameters.get("app") +"] is being deleted" );
        }
    }
}
