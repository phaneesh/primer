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

package io.jwt.primer.util;

import io.jwt.primer.exception.PrimerException;
import org.apache.commons.lang.exception.ExceptionUtils;

/**
 * @author phaneesh
 */
public interface PrimerExceptionUtil {

    static void handleException(Exception e) throws PrimerException {
        if(e instanceof PrimerException) {
            throw (PrimerException)e;
        }
        if(ExceptionUtils.getRootCause(e) instanceof PrimerException) {
            throw (PrimerException)ExceptionUtils.getRootCause(e);
        }
    }
}
