/*
 * (c) Copyright 2023 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.atlasdb.workload.workflow.ring;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.palantir.atlasdb.workload.store.ImmutableWorkloadCell;
import com.palantir.atlasdb.workload.store.InteractiveTransactionStore;
import com.palantir.atlasdb.workload.transaction.InteractiveTransaction;
import com.palantir.atlasdb.workload.transaction.witnessed.WitnessedTransaction;
import com.palantir.atlasdb.workload.workflow.DefaultWorkflow;
import com.palantir.atlasdb.workload.workflow.Workflow;
import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.logger.SafeLogger;
import com.palantir.logsafe.logger.SafeLoggerFactory;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public final class RingWorkflows {

    private static final SafeLogger log = SafeLoggerFactory.get(RingWorkflows.class);

    private static final int COLUMN = 0;

    private RingWorkflows() {
        // static factory
    }

    public static Workflow create(
            InteractiveTransactionStore store,
            RingWorkflowConfiguration ringWorkflowConfiguration,
            ListeningExecutorService executionExecutor) {
        return DefaultWorkflow.create(
                store,
                (txnStore, _index) -> run(txnStore, ringWorkflowConfiguration),
                ringWorkflowConfiguration,
                executionExecutor);
    }

    private static Optional<WitnessedTransaction> run(
            InteractiveTransactionStore store, RingWorkflowConfiguration workflowConfiguration) {
        workflowConfiguration.transactionRateLimiter().acquire();
        String table = workflowConfiguration.tableConfiguration().tableName();
        Integer ringSize = workflowConfiguration.ringSize();
        return store.readWrite(txn -> {
            Map<Integer, Optional<Integer>> data = fetchData(table, ringSize, txn);
            RingGraph ringGraph = RingGraph.fromPartial(data);
            ringGraph
                    .validate()
                    .ifPresent(ringError ->
                            log.error("Detected violation with our ring {}", SafeArg.of("ringError", ringError)));
            ringGraph.createOrShuffle().forEach((rootNode, nextNode) -> txn.write(table, cell(rootNode), nextNode));
        });
    }

    private static Map<Integer, Optional<Integer>> fetchData(
            String table, int ringSize, InteractiveTransaction transaction) {
        return IntStream.range(0, ringSize)
                .boxed()
                .collect(Collectors.toMap(Function.identity(), index -> transaction.read(table, cell(index))));
    }

    @VisibleForTesting
    static ImmutableWorkloadCell cell(Integer node) {
        return ImmutableWorkloadCell.of(node, COLUMN);
    }
}
