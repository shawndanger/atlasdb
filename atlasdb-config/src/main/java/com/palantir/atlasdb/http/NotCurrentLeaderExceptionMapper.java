/*
 * (c) Copyright 2018 Palantir Technologies Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.palantir.atlasdb.http;

import java.time.Duration;
import java.util.Optional;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

import com.palantir.leader.NotCurrentLeaderException;

/**
 * Convert {@link NotCurrentLeaderException} into a 503 status response.
 *
 * @author carrino
 */
public class NotCurrentLeaderExceptionMapper implements ExceptionMapper<NotCurrentLeaderException> {
    /**
     * Returns a response equal to a response when encountering a
     * {@link com.palantir.conjure.java.api.errors.QosException.Unavailable} exception.
     */
    @Override
    public Response toResponse(NotCurrentLeaderException exception) {
        return ExceptionMappers.encodeAsUnavailable(exception, Optional.of(Duration.ofMillis(50)));
    }
}
