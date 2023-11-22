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
package com.palantir.atlasdb.schema;

import com.google.common.base.Preconditions;
import com.google.common.collect.Sets;
import com.google.common.util.concurrent.Futures;
import com.palantir.atlasdb.keyvalue.api.Cell;
import com.palantir.atlasdb.keyvalue.api.KeyValueService;
import com.palantir.atlasdb.keyvalue.api.RangeRequest;
import com.palantir.atlasdb.keyvalue.api.RangeRequests;
import com.palantir.atlasdb.keyvalue.api.RowResult;
import com.palantir.atlasdb.keyvalue.api.TableReference;
import com.palantir.atlasdb.keyvalue.impl.Cells;
import com.palantir.atlasdb.logging.LoggingArgs;
import com.palantir.atlasdb.schema.KeyValueServiceMigrator.KvsMigrationMessageLevel;
import com.palantir.atlasdb.schema.KeyValueServiceMigrator.KvsMigrationMessageProcessor;
import com.palantir.atlasdb.transaction.api.Transaction;
import com.palantir.atlasdb.transaction.api.TransactionManager;
import com.palantir.common.base.BatchingVisitableView;
import com.palantir.common.base.Throwables;
import com.palantir.common.concurrent.PTExecutors;
import com.palantir.logsafe.SafeArg;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class KeyValueServiceValidator {
    private final TransactionManager validationFromTransactionManager;
    private final TransactionManager validationToTransactionManager;
    private final KeyValueService validationFromKvs;

    private final int threads;
    private final int defaultBatchSize;

    // Tables that exist on the legacy KVS and should not be migrated.
    // TODO(tgordeeva): hacky, clean this up when we have table specific migration
    private final Set<TableReference> unmigratableTables;

    private final Map<TableReference, Integer> readBatchSizeOverrides;

    private final KvsMigrationMessageProcessor messageProcessor;

    private final AtomicInteger migratedTableCount;

    public KeyValueServiceValidator(
            TransactionManager validationFromTransactionManager,
            TransactionManager validationToTransactionManager,
            KeyValueService validationFromKvs,
            int threads,
            int defaultBatchSize,
            Map<TableReference, Integer> readBatchSizeOverrides,
            KvsMigrationMessageProcessor messageProcessor,
            Set<TableReference> unmigratableTables,
            AtomicInteger migratedTableCount) {
        this.validationFromTransactionManager = validationFromTransactionManager;
        this.validationToTransactionManager = validationToTransactionManager;
        this.validationFromKvs = validationFromKvs;
        this.threads = threads;
        this.defaultBatchSize = defaultBatchSize;
        this.readBatchSizeOverrides = readBatchSizeOverrides;
        this.messageProcessor = messageProcessor;
        this.unmigratableTables = unmigratableTables;
        this.migratedTableCount = migratedTableCount;
    }

    private int getBatchSize(TableReference table) {
        Integer batchSize = readBatchSizeOverrides.get(table);
        return batchSize != null ? batchSize : defaultBatchSize;
    }

    public void validate(boolean logOnly) {
        Set<String> tablesToIgnore = Set.of(
                "multipass.allowedClients_idx",
                "multipass.apiMigration",
                "multipass.apiTokenExpirations_v2_aidx",
                "multipass.apiTokens",
                "multipass.apiTokens_v3",
                "multipass.authCodeStringToAuthCode",
                "multipass.authenticationProviders",
                "multipass.cbacMetadata",
                "multipass.cbacXml",
                "multipass.challengeAuthResult",
                "multipass.challengesBySessionIdV2_idx",
                "multipass.challengeSessionsV4",
                "multipass.challengesV2",
                "multipass.changelogIdsByPrincipalIds_idx",
                "multipass.changelogPopulatorSequencePoints",
                "multipass.clientIdToClientTransferRequests_idx",
                "multipass.clientInstallations",
                "multipass.clients",
                "multipass.clientsByUserId_aidx",
                "multipass.clientTransferRequests",
                "multipass.concurrent_sessions",
                "multipass.consent",
                "multipass.consentRequestIds",
                "multipass.counter",
                "multipass.credentialCollectors",
                "multipass.deletedProviderGroups",
                "multipass.deletedProviderUsers",
                "multipass.duplicateProviderGroups",
                "multipass.existingDuplicateGroupsResolution",
                "multipass.groupIdUserIndex_idx",
                "multipass.groupMembershipChangeRequests",
                "multipass.groupNameShaRealmIndex_idx",
                "multipass.groupNameShaRealmIndex_v2_idx",
                "multipass.groupTemporaryMembers",
                "multipass.groupTemporaryMembersExpirations_idx",
                "multipass.groupTemporaryMembersIndex_idx",
                "multipass.hostSettings",
                "multipass.indexConsumerSequencePoints",
                "multipass.internalProviderIds",
                "multipass.internalUsers",
                "multipass.keys",
                "multipass.lastChallengeSessionInfo",
                "multipass.localRealms",
                "multipass.loginInfoV2",
                "multipass.markingAccessRequests",
                "multipass.messageIdsByBrowserId_idx",
                "multipass.migratedInternalUsers",
                "multipass.migrationBackupUsers",
                "multipass.multiFactorAuthResult",
                "multipass.multiFactorChallenges",
                "multipass.oganizationIdToClientId_idx",
                "multipass.oidcAuthStates",
                "multipass.oidcSessionByCreatedAt_aidx",
                "multipass.oidcSessionBySid_idx",
                "multipass.oidcSessionBySub_idx",
                "multipass.oidcSessions",
                "multipass.organization",
                "multipass.organizationIdByMarkingId_idx",
                "multipass.organizationIdToClientId_idx",
                "multipass.organizationIdToGroupId_idx",
                "multipass.organizationIdToPersonalClientId_idx",
                "multipass.organizationsByDisplayName_idx",
                "multipass.organizationTriagingGroupRules",
                "multipass.organizationTriagingUserRules",
                "multipass.orgIdToScopedSessionDefinitionId_idx",
                "multipass.ownerIdToClientId_idx",
                "multipass.ownerUserIdToClientId_idx",
                "multipass.ownerUserIdToPersonalClientId_idx",
                "multipass.preparedEvents",
                "multipass.preregisteredGroups",
                "multipass.preregisteredUsers",
                "multipass.preregisteredUsersByPrincipalId_idx",
                "multipass.preregisteredUsers_v2",
                "multipass.principalIdSessionIndex_idx",
                "multipass.principalIdSessionIndex_v2_idx",
                "multipass.principalIdToBrowserIds_idx",
                "multipass.principalIdToGroup",
                "multipass.principalIdToGroup_v2",
                "multipass.principalIdToGroup_v4",
                "multipass.principalIdToUserV2",
                "multipass.principalsToContainingGroups",
                "multipass.principalToRefreshSessions",
                "multipass.principalToUserGeneratedApiTokens",
                "multipass.providerGroupIdAndRealmToPrincipalId",
                "multipass.providerGroupIdRealmToPrincipalId_v2",
                "multipass.providerUsers",
                "multipass.pUserToUserIntakeFormSubmissions",
                "multipass.realmGroupIndex_idx",
                "multipass.realmGroupIndex_v2_idx",
                "multipass.realmIndex_idx",
                "multipass.refreshSessionExpirations_aidx",
                "multipass.refreshSessions",
                "multipass.refreshTokenExpirations_aidx",
                "multipass.refreshTokenExpirations_v2_aidx",
                "multipass.refreshTokens",
                "multipass.remoteEntities",
                "multipass.remoteIds_idx",
                "multipass.remoteRealms_idx",
                "multipass.samlAuthnStates",
                "multipass.samlLogoutStates",
                "multipass.samlSessions",
                "multipass.scopedSessionDefinitions",
                "multipass.scopedSessionOrganizationInfo",
                "multipass.searchAvailableVersions",
                "multipass.searchIndexChangelog",
                "multipass.sessionExpirations_v2_aidx",
                "multipass.sessions",
                "multipass.sessions_v2",
                "multipass.sic_stream_hash_aidx",
                "multipass.sic_stream_idx",
                "multipass.sic_stream_metadata",
                "multipass.sic_stream_value",
                "multipass.stagedAttributes",
                "multipass.stagedAttributes_v2",
                "multipass.upgradeSession",
                "multipass_upgrades.upgrades",
                "multipass_upgrades.upgradesByVersion_idx",
                "multipass_upgrades.version",
                "multipass.userIntakeFormConfigurations",
                "multipass.userIntakeFormSubmissionMetadata",
                "multipass.userIntakeFormSubmissions",
                "multipass.usernameShaRealmIndex_idx",
                "multipass.userToUserIntakeFormSubmissions_idx",
                "sequential.sequential_ordered",
                "gatekeeper_v2.changeLogMetadataV2",
                "sequential.stores_to_drop",
                "gatekeeper_v2.changeLog",
                "gatekeeper_v2.categories",
                "gatekeeper_v2.rolesByNameV3_idx",
                "gatekeeper_v2.globalMarkingId_idx",
                "gatekeeper_v2.ConfigRoleTemplate",
                "gatekeeper_v2.markingCategoryIndex",
                "gatekeeper_v2.roleIdsV2",
                "gatekeeper_v2.sequenceKey",
                "gatekeeper_v2.rolesV2",
                "sequential.deletion_progress",
                "sequential.sequential_offsets",
                "compact.metadata",
                "gatekeeper_v2.rolesV3",
                "gatekeeper_v2.roleSets",
                "liveMigration.schema_lease_version_store",
                "gatekeeper_v2.rolesV4",
                "gatekeeper_v2.sequence",
                "gatekeeper_v2.resources",
                "gatekeeper_v2.ConfigWorkflow",
                "gatekeeper_v2.markings",
                "gatekeeper_v2.categoryGroupIndex",
                "gatekeeper_v2.miscellaneousIds",
                "gatekeeper_v2.roles",
                "gatekeeper_v2.rolesByNameV2_idx",
                "gatekeeper_v2.InitialNodes",
                "gatekeeper_v2.InitialNodeAdditions",
                "sequential.sequential_pending",
                "gatekeeper_v2.rollableMigrations",
                "sequential.buckets",
                "gatekeeper_v2.rolesByRoleSetId_idx",
                "gatekeeper_v2.sic_stream_hash_aidx",
                "gatekeeper_v2.sequence_v2",
                "gatekeeper_v2.sic_stream_metadata",
                "gatekeeper_v2.markingGroupIndex",
                "gatekeeper_v2.rc_stream_hash_aidx",
                "gatekeeper_v2.Expansions",
                "gatekeeper_v2.rc_stream_metadata",
                "gatekeeper_v2.sic_stream_idx",
                "gatekeeper_v2.rc_stream_idx",
                "gatekeeper_v2.rolesActivityMetadata",
                "gatekeeper_v2.strings",
                "gatekeeper_v2.stringsById_idx",
                "gatekeeper_v2.sic_stream_value",
                "liveMigration.consensus_store",
                "gatekeeper_v2.rc_stream_value");
        Set<TableReference> asTableReferences =
                tablesToIgnore.stream().map(TableReference::fromString).collect(Collectors.toSet());
        Set<TableReference> tables =
                KeyValueServiceValidators.getValidatableTableNames(validationFromKvs, unmigratableTables);
        Set<TableReference> remainingTables = Sets.difference(tables, asTableReferences);
        Set<TableReference> missingTables = Sets.difference(asTableReferences, tables);
        com.palantir.logsafe.Preconditions.checkArgument(
                missingTables.isEmpty(),
                "Not all tables were found, which means we made a mistake in transcription.",
                SafeArg.of("nonexistenttables", missingTables),
                SafeArg.of("allTables", tables));

        try {
            validateTables(remainingTables);
        } catch (Throwable t) {
            KeyValueServiceMigratorUtils.processMessage(
                    messageProcessor, "Validation failed.", t, KvsMigrationMessageLevel.ERROR);
            if (!logOnly) {
                throw Throwables.throwUncheckedException(t);
            }
        }
    }

    private void validateTables(Set<TableReference> tables) {
        ExecutorService executor = PTExecutors.newFixedThreadPool(threads);
        List<Future<Void>> futures = new ArrayList<>();
        for (final TableReference table : tables) {
            Future<Void> future = executor.submit(() -> {
                try {
                    validateTable(table);
                    KeyValueServiceMigratorUtils.processMessage(
                            messageProcessor,
                            "Validated a table {} ({} of {})",
                            KvsMigrationMessageLevel.INFO,
                            LoggingArgs.tableRef(table),
                            SafeArg.of("migratedTableCount", migratedTableCount.incrementAndGet()),
                            SafeArg.of("totalTables", tables.size()));
                } catch (RuntimeException e) {
                    throw Throwables.rewrapAndThrowUncheckedException("Exception while validating " + table, e);
                }
                return null;
            });
            futures.add(future);
        }

        futures.forEach(Futures::getUnchecked);
        KeyValueServiceMigratorUtils.processMessage(
                messageProcessor, "Validation complete.", KvsMigrationMessageLevel.INFO);
    }

    private void validateTable(final TableReference table) {
        final int limit = getBatchSize(table);
        // read only, but need to use a write tx in case the source table has SweepStrategy.THOROUGH
        byte[] nextRowName = new byte[0];
        while (nextRowName != null) {
            nextRowName = validateNextBatchOfRows(table, limit, nextRowName);
            KeyValueServiceMigratorUtils.processMessage(
                    messageProcessor,
                    "Validated a batch of rows for {}",
                    KvsMigrationMessageLevel.INFO,
                    LoggingArgs.tableRef(table));
        }
    }

    private byte[] validateNextBatchOfRows(TableReference table, int limit, byte[] nextRowName) {
        try {
            // read only, but need to use a write tx in case the source table has SweepStrategy.THOROUGH
            return validationFromTransactionManager.runTaskWithRetry(
                    t1 -> validationToTransactionManager.runTaskWithRetry(t2 -> {
                        RangeRequest range = RangeRequest.builder()
                                .batchHint(limit)
                                .startRowInclusive(nextRowName)
                                .build();
                        return validateAndGetNextRowName(table, limit, t1, t2, range);
                    }));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] validateAndGetNextRowName(
            TableReference table, int limit, Transaction t1, Transaction t2, RangeRequest range) {
        BatchingVisitableView<RowResult<byte[]>> bv1 = BatchingVisitableView.of(t1.getRange(table, range));
        List<RowResult<byte[]>> rrs1 = bv1.limit(limit).immutableCopy();
        Map<Cell, byte[]> cells1 = Cells.convertRowResultsToCells(rrs1);

        BatchingVisitableView<RowResult<byte[]>> bv2 = BatchingVisitableView.of(t2.getRange(table, range));
        List<RowResult<byte[]>> rrs2 = bv2.limit(limit).immutableCopy();
        Map<Cell, byte[]> cells2 = Cells.convertRowResultsToCells(rrs2);

        validateEquality(cells1, cells2);

        if (rrs1.isEmpty()) {
            return null;
        }

        byte[] lastRow = rrs1.get(rrs1.size() - 1).getRowName();
        if (RangeRequests.isLastRowName(lastRow)) {
            return null;
        }
        return RangeRequests.nextLexicographicName(lastRow);
    }

    private void validateEquality(Map<Cell, byte[]> cells1, Map<Cell, byte[]> cells2) {
        Set<Cell> ks1 = cells1.keySet();
        Set<Cell> ks2 = cells2.keySet();
        Preconditions.checkArgument(ks1.equals(ks2), "Cells not equal. Expected: %s. Actual: %s", ks1, ks2);
        for (Cell c : ks1) {
            Preconditions.checkArgument(Arrays.equals(cells1.get(c), cells2.get(c)), "Values not equal for cell %s", c);
        }
    }
}
