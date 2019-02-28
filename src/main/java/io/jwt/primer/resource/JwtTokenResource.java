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
import com.google.common.base.Strings;
import io.jwt.primer.command.PrimerCommands;
import io.jwt.primer.config.AerospikeConfig;
import io.jwt.primer.config.JwtConfig;
import io.jwt.primer.exception.PrimerException;
import io.jwt.primer.model.*;
import io.jwt.primer.util.PrimerExceptionUtil;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.extern.slf4j.Slf4j;

import javax.inject.Singleton;
import javax.validation.Valid;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * @author phaneesh
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Slf4j
@Singleton
@Api(value = "JWT Token Management API")
public class JwtTokenResource {

    private final HmacSHA512Signer signer;

    private final JwtConfig jwtConfig;

    private final AerospikeConfig aerospikeConfig;



    public JwtTokenResource(final JwtConfig jwtConfig, final AerospikeConfig aerospikeConfig) {
        this.jwtConfig = jwtConfig;
        this.aerospikeConfig = aerospikeConfig;
        this.signer = new HmacSHA512Signer(jwtConfig.getPrivateKey().getBytes(Charsets.UTF_8));
    }

    @POST
    @Path("/v1/jwt/generate/{app}")
    @ApiOperation(value = "Generate JWT token")
    @ApiResponses({
            @ApiResponse(code = 200, response = TokenResponse.class, message = "Success"),
            @ApiResponse(code = 500, response = PrimerError.class, message = "Error"),
    })
    @Metered
    public TokenResponse generate(@PathParam("app") String app, @Valid JwtTokenRequest request) throws PrimerException {
        try {
            return PrimerCommands.generateJwt(aerospikeConfig, app, request, jwtConfig, signer);
        } catch (Exception e) {
            PrimerExceptionUtil.handleException(e);
            log.error("Execution Error generating token", e);
            throw new PrimerException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "PR001", "Error");
        }
    }


    @POST
    @Path("/v1/jwt/refresh/{app}/{id}")
    @ApiOperation(value = "Refresh JWT Token")
    public RefreshResponse refresh(@HeaderParam("X-Auth-Token") String token,
                                   @HeaderParam("X-Refresh-Token") String refresh, @PathParam("app") String app,
                                   @PathParam("id") String id) throws PrimerException {
        try {
            JwtToken jwtToken = PrimerCommands.getJwt(aerospikeConfig, app, id);
            if (jwtToken == null)
                throw new PrimerException(Response.Status.NOT_FOUND.getStatusCode(), "PR001", "Not Found");
            if (!jwtToken.isEnabled()) {
                throw new PrimerException(Response.Status.FORBIDDEN.getStatusCode(), "PR002", "Forbidden");
            }
            if (jwtToken.getToken().equals(token) && jwtToken.getRefreshToken().equals(refresh)) {
                return PrimerCommands.refreshJwt(aerospikeConfig, app, id, jwtToken, jwtConfig, signer);
            } else {
                if (!Strings.isNullOrEmpty(jwtToken.getPreviousToken()) && !Strings.isNullOrEmpty(jwtToken.getPreviousRefreshToken())) {
                    if (jwtToken.getPreviousToken().equals(token) && jwtToken.getPreviousRefreshToken().equals(refresh)) {
                        return PrimerCommands.refreshJwt(aerospikeConfig, app, id, jwtToken, jwtConfig, signer);
                    }
                }
                throw new PrimerException(Response.Status.UNAUTHORIZED.getStatusCode(), "PR004", "Unauthorized");
            }
        } catch (Exception e) {
            PrimerExceptionUtil.handleException(e);
            log.error("Execution Error refreshing token", e);
            throw new PrimerException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "PR001", "Error");
        }
    }


    @POST
    @Path("/v1/jwt/disable/{app}/{id}")
    @ApiOperation(value = "Disable Primer token")
    @ApiResponses({
            @ApiResponse(code = 200, response = TokenDisableResponse.class, message = "Success"),
            @ApiResponse(code = 500, response = PrimerError.class, message = "Error"),
    })
    @Metered
    public TokenDisableResponse disable(@PathParam("id") String id,
                                        @PathParam("app") String app) throws PrimerException {
        try {
            TokenDisableResponse response = PrimerCommands.disableJwt(aerospikeConfig, app, id);
            if(response == null) {
                throw new PrimerException(Response.Status.NOT_FOUND.getStatusCode(), "PR001", "Not Found");
            }
            return response;
        } catch (Exception e) {
            PrimerExceptionUtil.handleException(e);
            log.error("Execution Error disabling token", e);
            throw new PrimerException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "PR001", "Error");
        }
    }

    @DELETE
    @Path("/v1/jwt/clear/{app}/{id}")
    @ApiOperation(value = "Clear JWT token")
    @ApiResponses({
            @ApiResponse(code = 200, response = TokenClearResponse.class, message = "Success"),
            @ApiResponse(code = 500, response = PrimerError.class, message = "Error"),
    })
    @Metered
    public TokenClearResponse clear(@PathParam("id") String id,
                                    @PathParam("app") String app) throws PrimerException {
        try {
            TokenClearResponse response = PrimerCommands.clearJwt(aerospikeConfig, app, id);
            if(response == null) {
                throw new PrimerException(Response.Status.NOT_FOUND.getStatusCode(), "PR001", "Not Found");
            }
            return response;
        } catch (Exception e) {
            PrimerExceptionUtil.handleException(e);
            log.error("Execution Error clearing token", e);
            throw new PrimerException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "PR001", "Error");
        }
    }

    @POST
    @Path("/v1/jwt/expire/{app}/{id}")
    @ApiOperation(value = "Expire Primer token for given user")
    @ApiResponses({
            @ApiResponse(code = 200, response = TokenExpireResponse.class, message = "Success"),
            @ApiResponse(code = 404, response = PrimerError.class, message = "Not Found"),
            @ApiResponse(code = 500, response = PrimerError.class, message = "Error"),
    })
    @Metered
    public TokenExpireResponse expire(@PathParam("id") String id,
                                      @PathParam("app") String app) throws PrimerException {
        try {
            TokenExpireResponse response = PrimerCommands.expireJwt(aerospikeConfig, app, id);
            if(response == null) {
                throw new PrimerException(Response.Status.NOT_FOUND.getStatusCode(), "PR001", "Not Found");
            }
            return response;
        } catch (Exception e) {
            PrimerExceptionUtil.handleException(e);
            log.error("Execution Error disabling token", e);
            throw new PrimerException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "PR001", "Error");
        }
    }

}
