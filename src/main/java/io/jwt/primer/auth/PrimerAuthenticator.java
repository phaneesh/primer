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

package io.jwt.primer.auth;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenValidator;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.validator.ExpiryValidator;
import com.google.common.collect.ImmutableList;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.jwt.primer.model.ServiceUser;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;


/**
 * @author phaneesh
 */
@Slf4j
public class PrimerAuthenticator implements Authenticator<JsonWebToken, ServiceUser> {

    private final ImmutableList<JsonWebTokenValidator> validators
            = ImmutableList.<JsonWebTokenValidator>builder()
            .add(new ExpiryValidator())
            .build();

    @Override
    public Optional<ServiceUser> authenticate(JsonWebToken jsonWebToken) throws AuthenticationException {

        for(JsonWebTokenValidator validator : validators) {
            try {
                validator.validate(jsonWebToken);
            } catch (Throwable t) {
                log.warn("Validation failed for token {}: {}", validator.getClass().getSimpleName(), t.getMessage());
                return Optional.empty();
            }
            log.info("Passed: {}", validator.getClass().getSimpleName());
        }
        return Optional.of(ServiceUser.builder()
                .name("phonepe")
                .build());
    }

}
