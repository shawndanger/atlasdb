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

package com.palantir.atlasdb.workload.transaction;

import com.palantir.atlasdb.keyvalue.api.Namespace;
import com.palantir.atlasdb.keyvalue.api.TableReference;
import com.palantir.atlasdb.workload.store.ImmutableWorkloadCell;
import com.palantir.atlasdb.workload.store.TableAndWorkloadCell;
import com.palantir.atlasdb.workload.store.WorkloadCell;

public final class WorkloadTestHelpers {
    public static final String TABLE = "foo";
    public static final String INDEX_TABLE = TABLE + "_index";
    public static final TableReference TABLE_REFERENCE = TableReference.create(Namespace.DEFAULT_NAMESPACE, TABLE);
    public static final TableReference INDEX_REFERENCE =
            TableReference.create(TABLE_REFERENCE.getNamespace(), INDEX_TABLE);
    public static final WorkloadCell WORKLOAD_CELL_ONE = ImmutableWorkloadCell.of(50, 10);
    public static final WorkloadCell WORKLOAD_CELL_TWO = ImmutableWorkloadCell.of(1257, 521);
    public static final WorkloadCell WORKLOAD_CELL_THREE =
            ImmutableWorkloadCell.builder().key(567).column(405234).build();
    public static final Integer VALUE_ONE = 541;
    public static final Integer VALUE_TWO = 334;
    public static final TableAndWorkloadCell TABLE_WORKLOAD_CELL_ONE =
            TableAndWorkloadCell.of(TABLE, WORKLOAD_CELL_ONE);
    public static final TableAndWorkloadCell TABLE_WORKLOAD_CELL_TWO =
            TableAndWorkloadCell.of(TABLE, WORKLOAD_CELL_TWO);
}
