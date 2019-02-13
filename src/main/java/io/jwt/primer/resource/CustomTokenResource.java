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

package io.jwt.primer.resource;

import com.codahale.metrics.annotation.Metered;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.google.common.base.Charsets;
import io.jwt.primer.command.PrimerCommands;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.config.JwtConfig;
import io.jwt.primer.exception.PrimerException;
import io.jwt.primer.model.CustomTokenRequest;
import io.jwt.primer.model.PrimerError;
import io.jwt.primer.model.TokenResponse;
import io.jwt.primer.util.PrimerExceptionUtil;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.extern.slf4j.Slf4j;

import javax.inject.Singleton;
import javax.validation.Valid;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * @author phaneesh
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Slf4j
@Singleton
@Api(value = "Custom Token Management API")
public class CustomTokenResource {

    private final HmacSHA512Signer signer;

    private final JwtConfig jwtConfig;

    private final AerospikeConfig aerospikeConfig;

    public CustomTokenResource(final JwtConfig jwtConfig, final AerospikeConfig aerospikeConfig) {
        this.jwtConfig = jwtConfig;
        this.aerospikeConfig = aerospikeConfig;
        this.signer = new HmacSHA512Signer(jwtConfig.getPrivateKey().getBytes(Charsets.UTF_8));
    }

    @POST
    @Path("/v1/custom/generate/{app}")
    @ApiOperation(value = "Generate a custom JWT token for given user")
    @ApiResponses({
            @ApiResponse(code = 200, response = TokenResponse.class, message = "Success"),
            @ApiResponse(code = 500, response = PrimerError.class, message = "Error"),
    })
    @Metered
    public TokenResponse generate(@PathParam("app") String app, @Valid CustomTokenRequest request) throws PrimerException {
        try {
            return PrimerCommands.generateCustom(aerospikeConfig, app, request, jwtConfig, signer);
        } catch (Exception e) {
            PrimerExceptionUtil.handleException(e);
            log.error("Execution Error generating token", e);
            throw new PrimerException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "PR001", "Error");
        }
    }
}
