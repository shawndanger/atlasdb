/*
 * (c) Copyright 2020 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.atlasdb.debug;

import com.palantir.atlasdb.timelock.api.ConjureGetFreshTimestampResponse;
import com.palantir.atlasdb.timelock.api.ConjureGetFreshTimestampsRequest;
import com.palantir.atlasdb.timelock.api.ConjureGetFreshTimestampsResponse;
import com.palantir.atlasdb.timelock.api.ConjureLockRequest;
import com.palantir.atlasdb.timelock.api.ConjureLockResponse;
import com.palantir.atlasdb.timelock.api.ConjureLockResponseV2;
import com.palantir.atlasdb.timelock.api.ConjureLockResponseV2.Visitor;
import com.palantir.atlasdb.timelock.api.ConjureLockToken;
import com.palantir.atlasdb.timelock.api.ConjureRefreshLocksRequest;
import com.palantir.atlasdb.timelock.api.ConjureRefreshLocksRequestV2;
import com.palantir.atlasdb.timelock.api.ConjureRefreshLocksResponse;
import com.palantir.atlasdb.timelock.api.ConjureRefreshLocksResponseV2;
import com.palantir.atlasdb.timelock.api.ConjureStartOneTransactionRequest;
import com.palantir.atlasdb.timelock.api.ConjureStartOneTransactionResponse;
import com.palantir.atlasdb.timelock.api.ConjureStartTransactionsRequest;
import com.palantir.atlasdb.timelock.api.ConjureStartTransactionsResponse;
import com.palantir.atlasdb.timelock.api.ConjureTimelockService;
import com.palantir.atlasdb.timelock.api.ConjureUnlockRequest;
import com.palantir.atlasdb.timelock.api.ConjureUnlockRequestV2;
import com.palantir.atlasdb.timelock.api.ConjureUnlockResponse;
import com.palantir.atlasdb.timelock.api.ConjureUnlockResponseV2;
import com.palantir.atlasdb.timelock.api.ConjureWaitForLocksResponse;
import com.palantir.atlasdb.timelock.api.GetCommitTimestampsRequest;
import com.palantir.atlasdb.timelock.api.GetCommitTimestampsResponse;
import com.palantir.atlasdb.timelock.api.GetOneCommitTimestampRequest;
import com.palantir.atlasdb.timelock.api.GetOneCommitTimestampResponse;
import com.palantir.atlasdb.timelock.api.SuccessfulLockResponse;
import com.palantir.atlasdb.timelock.api.SuccessfulLockResponseV2;
import com.palantir.atlasdb.timelock.api.UnsuccessfulLockResponse;
import com.palantir.lock.v2.LeaderTime;
import com.palantir.logsafe.exceptions.SafeIllegalStateException;
import com.palantir.tokens.auth.AuthHeader;
import java.io.InputStream;
import java.util.Optional;
import java.util.stream.LongStream;
import javax.ws.rs.core.StreamingOutput;

/**
 * TODO(fdesouza): Remove this once PDS-95791 is resolved.
 * @deprecated Remove this once PDS-95791 is resolved.
 */
@Deprecated
public class LockDiagnosticConjureTimelockService implements ConjureTimelockService {
    private final ConjureTimelockService conjureDelegate;
    private final ClientLockDiagnosticCollector lockDiagnosticCollector;
    private final LocalLockTracker localLockTracker;

    public LockDiagnosticConjureTimelockService(
            ConjureTimelockService conjureDelegate,
            ClientLockDiagnosticCollector lockDiagnosticCollector,
            LocalLockTracker localLockTracker) {
        this.conjureDelegate = conjureDelegate;
        this.lockDiagnosticCollector = lockDiagnosticCollector;
        this.localLockTracker = localLockTracker;
    }

    @Override
    public ConjureStartTransactionsResponse startTransactions(
            AuthHeader authHeader, String namespace, ConjureStartTransactionsRequest request) {
        ConjureStartTransactionsResponse response = conjureDelegate.startTransactions(authHeader, namespace, request);
        lockDiagnosticCollector.collect(
                response.getTimestamps().stream(),
                response.getImmutableTimestamp().getImmutableTimestamp(),
                request.getRequestId());
        return response;
    }

    @Override
    public ConjureGetFreshTimestampsResponse getFreshTimestamps(
            AuthHeader authHeader, String namespace, ConjureGetFreshTimestampsRequest request) {
        return conjureDelegate.getFreshTimestamps(authHeader, namespace, request);
    }

    @Override
    public ConjureStartOneTransactionResponse startOneTransaction(
            AuthHeader authHeader, String namespace, ConjureStartOneTransactionRequest request) {
        ConjureStartOneTransactionResponse response =
                conjureDelegate.startOneTransaction(authHeader, namespace, request);
        lockDiagnosticCollector.collect(
                LongStream.of(response.getTimestamp()),
                response.getImmutableTimestamp().getImmutableTimestamp(),
                request.getRequestId());
        return response;
    }

    @Override
    public ConjureGetFreshTimestampResponse getFreshTimestamp(AuthHeader authHeader, String namespace) {
        return conjureDelegate.getFreshTimestamp(authHeader, namespace);
    }

    @Override
    public LeaderTime leaderTime(AuthHeader authHeader, String namespace) {
        return conjureDelegate.leaderTime(authHeader, namespace);
    }

    @Override
    public ConjureLockResponse lock(AuthHeader authHeader, String namespace, ConjureLockRequest request) {
        request.getClientDescription()
                .flatMap(LockDiagnosticConjureTimelockService::tryParseStartTimestamp)
                .ifPresent(startTimestamp -> lockDiagnosticCollector.collect(
                        startTimestamp, request.getRequestId(), request.getLockDescriptors()));
        ConjureLockResponse response = conjureDelegate.lock(authHeader, namespace, request);
        localLockTracker.logLockResponse(request.getLockDescriptors(), response);
        return response;
    }

    @Override
    public ConjureLockResponseV2 lockV2(AuthHeader authHeader, String namespace, ConjureLockRequest request) {
        request.getClientDescription()
                .flatMap(LockDiagnosticConjureTimelockService::tryParseStartTimestamp)
                .ifPresent(startTimestamp -> lockDiagnosticCollector.collect(
                        startTimestamp, request.getRequestId(), request.getLockDescriptors()));
        ConjureLockResponseV2 response = conjureDelegate.lockV2(authHeader, namespace, request);
        localLockTracker.logLockResponse(request.getLockDescriptors(), response.accept(new Visitor<>() {
            @Override
            public ConjureLockResponse visitSuccessful(SuccessfulLockResponseV2 value) {
                return ConjureLockResponse.successful(SuccessfulLockResponse.of(
                        ConjureLockToken.of(value.getLockToken().get()), value.getLease()));
            }

            @Override
            public ConjureLockResponse visitUnsuccessful(UnsuccessfulLockResponse value) {
                return ConjureLockResponse.unsuccessful(value);
            }

            @Override
            public ConjureLockResponse visitUnknown(String unknownType) {
                throw new SafeIllegalStateException("Encountered unknown lock response type");
            }
        }));
        return response;
    }

    @Override
    public ConjureWaitForLocksResponse waitForLocks(
            AuthHeader authHeader, String namespace, ConjureLockRequest request) {
        request.getClientDescription()
                .flatMap(LockDiagnosticConjureTimelockService::tryParseStartTimestamp)
                .ifPresent(startTimestamp -> lockDiagnosticCollector.collect(
                        startTimestamp, request.getRequestId(), request.getLockDescriptors()));
        ConjureWaitForLocksResponse response = conjureDelegate.waitForLocks(authHeader, namespace, request);
        localLockTracker.logWaitForLocksResponse(request.getLockDescriptors(), response);
        return response;
    }

    @Override
    public ConjureRefreshLocksResponse refreshLocks(
            AuthHeader authHeader, String namespace, ConjureRefreshLocksRequest request) {
        ConjureRefreshLocksResponse response = conjureDelegate.refreshLocks(authHeader, namespace, request);
        localLockTracker.logRefreshResponse(request.getTokens(), response);
        return response;
    }

    @Override
    public ConjureRefreshLocksResponseV2 refreshLocksV2(
            AuthHeader authHeader, String namespace, ConjureRefreshLocksRequestV2 request) {
        ConjureRefreshLocksResponseV2 response = conjureDelegate.refreshLocksV2(authHeader, namespace, request);
        localLockTracker.logRefreshResponse(request.get(), response.getRefreshedTokens());
        return response;
    }

    @Override
    public ConjureUnlockResponse unlock(AuthHeader authHeader, String namespace, ConjureUnlockRequest request) {
        ConjureUnlockResponse response = conjureDelegate.unlock(authHeader, namespace, request);
        localLockTracker.logUnlockResponse(request.getTokens(), response);
        return response;
    }

    @Override
    public ConjureUnlockResponseV2 unlockV2(AuthHeader authHeader, String namespace, ConjureUnlockRequestV2 request) {
        ConjureUnlockResponseV2 response = conjureDelegate.unlockV2(authHeader, namespace, request);
        localLockTracker.logUnlockResponse(request.get(), response.get());
        return response;
    }

    @Override
    public GetCommitTimestampsResponse getCommitTimestamps(
            AuthHeader authHeader, String namespace, GetCommitTimestampsRequest request) {
        return conjureDelegate.getCommitTimestamps(authHeader, namespace, request);
    }

    @Override
    public GetOneCommitTimestampResponse getOneCommitTimestamp(
            AuthHeader authHeader, String namespace, GetOneCommitTimestampRequest request) {
        return conjureDelegate.getOneCommitTimestamp(authHeader, namespace, request);
    }

    @Override
    public StreamingOutput runCommands(AuthHeader authHeader, String namespace, InputStream requests) {
        // Sorry.
        return conjureDelegate.runCommands(authHeader, namespace, requests);
    }

    private static Optional<Long> tryParseStartTimestamp(String description) {
        try {
            return Optional.of(Long.parseLong(description));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }
}
