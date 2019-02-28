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

package io.jwt.primer.model;

import lombok.*;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * @author phaneesh
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
@ToString
public class JwtToken {

    private String id;

    private String token;

    private String type;

    private String previousToken;

    private String refreshToken;

    private String previousRefreshToken;

    private String subject;

    private String name;

    private String role;

    private long expiry;

    private List<String> roles;

    private Map<String, Object> params;

    private Date issuedAt;

    private Date expiresAt;

    private boolean enabled;

}
