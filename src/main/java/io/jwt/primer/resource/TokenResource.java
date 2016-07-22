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
import io.jwt.primer.command.*;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.config.JwtConfig;
import io.jwt.primer.exception.PrimerException;
import io.jwt.primer.model.*;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.exception.ExceptionUtils;

import javax.inject.Singleton;
import javax.validation.Valid;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.time.Instant;

/**
 * @author phaneesh
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Slf4j
@Singleton
@Api(value = "Token Management API")
public class TokenResource {

    private final HmacSHA512Signer signer;

    private final JwtConfig jwtConfig;

    private final AerospikeConfig aerospikeConfig;

    public TokenResource(final JwtConfig jwtConfig, final AerospikeConfig aerospikeConfig) {
        this.jwtConfig = jwtConfig;
        this.aerospikeConfig = aerospikeConfig;
        this.signer = new HmacSHA512Signer(jwtConfig.getPrivateKey().getBytes(Charsets.UTF_8));
    }

    @POST
    @Path("/v1/generate/{app}")
    @ApiOperation(value = "Generate a JWT token for given user")
    @ApiResponses({
            @ApiResponse(code = 200, response = TokenResponse.class, message = "Success"),
            @ApiResponse(code = 500, response = PrimerError.class, message = "Error"),
    })
    @Metered
    public TokenResponse generate(@HeaderParam("X-User-Id") String id,
                                  @PathParam("app") String app, @Valid ServiceUser user) throws PrimerException {
        try {
            GenerateCommand generateCommand = new GenerateCommand(signer, jwtConfig, aerospikeConfig, id, app, user);
            return generateCommand.queue().get();
        } catch (Exception e) {
            log.error("Error generating token", e);
            throw new PrimerException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "PR000", e.getMessage());
        }
    }

    @POST
    @Path("/v1/disable/{app}/{id}")
    @ApiOperation(value = "Disable a JWT token for given user")
    @ApiResponses({
            @ApiResponse(code = 200, response = TokenDisableResponse.class, message = "Success"),
            @ApiResponse(code = 500, response = PrimerError.class, message = "Error"),
    })
    @Metered
    public TokenDisableResponse disable(@PathParam("id") String id,
                                        @PathParam("app") String app) throws PrimerException {
        try {
            DisableCommand disableCommand = new DisableCommand(aerospikeConfig, app, id);
            return disableCommand.queue().get();
        } catch (Exception e) {
            log.error("Error disabling token", e);
            if(ExceptionUtils.getRootCause(e) instanceof PrimerException) {
                throw (PrimerException)ExceptionUtils.getRootCause(e);
            }
            throw new PrimerException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "PR000", e.getMessage());
        }
    }

    @POST
    @Path("/v1/expire/{app}/{id}")
    @ApiOperation(value = "Expire a JWT token for given user")
    @ApiResponses({
            @ApiResponse(code = 200, response = TokenExpireResponse.class, message = "Success"),
            @ApiResponse(code = 404, response = PrimerError.class, message = "Not Found"),
            @ApiResponse(code = 500, response = PrimerError.class, message = "Error"),
    })
    @Metered
    public TokenExpireResponse expire(@PathParam("id") String id,
                                        @PathParam("app") String app) throws PrimerException {
        try {
            ExpireCommand expireCommand = new ExpireCommand(aerospikeConfig, app, id);
            return expireCommand.queue().get();
        } catch (Exception e) {
            log.error("Error disabling token", e);
            if(ExceptionUtils.getRootCause(e) instanceof PrimerException) {
                throw (PrimerException)ExceptionUtils.getRootCause(e);
            }
            throw new PrimerException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "PR000", e.getMessage());
        }
    }

    @GET
    @Path("/v1/token/{app}/{id}")
    @ApiOperation(value = "Get a JWT token for given user")
    @ApiResponses({
            @ApiResponse(code = 200, response = GetTokenResponse.class, message = "Success"),
            @ApiResponse(code = 404, response = PrimerError.class, message = "Not Found"),
            @ApiResponse(code = 500, response = PrimerError.class, message = "Error"),
    })
    @Metered
    public DynamicToken get(@PathParam("id") String id,
                                      @PathParam("app") String app) throws PrimerException {
        try {
            GetDynamicTokenCommand getDynamicTokenCommand = new GetDynamicTokenCommand(aerospikeConfig, app, id);
            DynamicToken dynamicToken = getDynamicTokenCommand.queue().get();
            if(dynamicToken == null)
                throw new PrimerException(Response.Status.NOT_FOUND.getStatusCode(), "PR001", "Not Found");
            return dynamicToken;
        } catch (Exception e) {
            log.error("Error getting token", e);
            if(ExceptionUtils.getRootCause(e) instanceof PrimerException) {
                throw (PrimerException)ExceptionUtils.getRootCause(e);
            }
            throw new PrimerException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "PR000", e.getMessage());
        }
    }

    @POST
    @Path("/v1/verify/{app}/{id}")
    @ApiOperation(value = "Verify the token for a given user")
    @ApiResponses({
            @ApiResponse(code = 200, response = VerifyResponse.class, message = "Success"),
            @ApiResponse(code = 401, response = PrimerError.class, message = "Unauthorized"),
            @ApiResponse(code = 404, response = PrimerError.class, message = "Not Found"),
            @ApiResponse(code = 403, response = PrimerError.class, message = "Forbidden"),
            @ApiResponse(code = 412, response = PrimerError.class, message = "Expired"),
            @ApiResponse(code = 500, response = PrimerError.class, message = "Error")
    })
    @Metered
    public VerifyResponse verify(@HeaderParam("X-Auth-Token") String token, @PathParam("app") String app,
                                 @PathParam("id") String id, @Valid ServiceUser user) throws PrimerException {
        try {
            GetDynamicTokenCommand getDynamicTokenCommand = new GetDynamicTokenCommand(aerospikeConfig, app, id);
            DynamicToken dynamicToken = getDynamicTokenCommand.queue().get();
            if(dynamicToken == null)
                throw new PrimerException(Response.Status.NOT_FOUND.getStatusCode(), "PR001", "Not Found");
            if(!dynamicToken.isEnabled()) {
                throw new PrimerException(Response.Status.FORBIDDEN.getStatusCode(), "PR002", "Forbidden");
            }
            final long adjusted = Instant.ofEpochSecond(dynamicToken.getExpiresAt().getTime()).plusSeconds(jwtConfig.getClockSkew()).getEpochSecond();
            final long now = Instant.now().getEpochSecond();
            if(adjusted <= now) {
                throw new PrimerException(Response.Status.PRECONDITION_FAILED.getStatusCode(), "PR003", "Expired");
            }
            if(token.equals(dynamicToken.getToken()) && user.getId().equals(dynamicToken.getSubject())
                    && user.getName().equals(dynamicToken.getName()) && user.getRole().equals(dynamicToken.getRole())) {
                return VerifyResponse.builder()
                        .expiresAt(dynamicToken.getExpiresAt().getTime())
                        .token(dynamicToken.getToken())
                        .userId(dynamicToken.getSubject())
                        .build();
            } else {
                throw new PrimerException(Response.Status.UNAUTHORIZED.getStatusCode(), "PR004", "Unauthorized");
            }
        } catch (Exception e) {
            log.error("Error verifying token", e);
            if(ExceptionUtils.getRootCause(e) instanceof PrimerException) {
                throw (PrimerException)ExceptionUtils.getRootCause(e);
            }
            throw new PrimerException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "PR001", "Error");
        }
    }

    @POST
    @Path("/v1/refresh/{app}/{id}")
    @ApiOperation(value = "Refresh the token for a given user")
    public RefreshResponse refresh(@HeaderParam("X-Auth-Token") String token,
                                   @HeaderParam("X-Refresh-Token") String refresh, @PathParam("app") String app,
                                   @PathParam("id") String id) throws PrimerException {
        try {
            GetDynamicTokenCommand getDynamicTokenCommand = new GetDynamicTokenCommand(aerospikeConfig, app, id);
            DynamicToken dynamicToken = getDynamicTokenCommand.queue().get();
            if(dynamicToken == null)
                throw new PrimerException(Response.Status.NOT_FOUND.getStatusCode(), "PR001", "Not Found");
            if(!dynamicToken.isEnabled()) {
                throw new PrimerException(Response.Status.FORBIDDEN.getStatusCode(), "PR002", "Forbidden");
            }
            if(dynamicToken.getToken().equals(token) && (dynamicToken.getRefreshToken().equals(refresh)
                    || dynamicToken.getPreviousRefreshToken().equals(refresh))) {
                RefreshCommand refreshCommand = new RefreshCommand(signer, jwtConfig, aerospikeConfig,
                        id, app, dynamicToken);
                return refreshCommand.queue().get();
            } else {
                throw new PrimerException(Response.Status.UNAUTHORIZED.getStatusCode(), "PR004", "Unauthorized");
            }
        } catch (Exception e) {
            log.error("Error refreshing token", e);
            if(ExceptionUtils.getRootCause(e) instanceof PrimerException) {
                throw (PrimerException)ExceptionUtils.getRootCause(e);
            }
            throw new PrimerException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "PR001", "Error");
        }
    }

}
