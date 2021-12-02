/*
 * (c) Copyright 2021 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.atlasdb.timelock.management;

import com.palantir.atlasdb.timelock.api.Namespace;
import com.palantir.paxos.SqliteConnections;
import javax.sql.DataSource;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.assertj.core.api.Assertions.assertThat;

public class DisabledNamespacesTest {
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private static final Namespace FIRST = Namespace.of("fst");
    private static final Namespace SECOND = Namespace.of("snd");

    private DataSource dataSource;
    private DisabledNamespaces disabledNamespaces;

    @Before
    public void setup() {
        dataSource = SqliteConnections.getDefaultConfiguredPooledDataSource(
                tempFolder.getRoot().toPath());
        disabledNamespaces = DisabledNamespaces.create(dataSource);
    }

    @Test
    public void notDisabledByDefault() {
        assertThat(disabledNamespaces.isDisabled(FIRST)).isFalse();
        assertThat(disabledNamespaces.isDisabled(SECOND)).isFalse();
        assertThat(disabledNamespaces.disabledNamespaces()).isEmpty();
    }

    @Test
    public void canDisableSingleNamespace() {
        disabledNamespaces.disable(FIRST);

        assertThat(disabledNamespaces.isDisabled(FIRST)).isTrue();
        assertThat(disabledNamespaces.isDisabled(SECOND)).isFalse();
        assertThat(disabledNamespaces.disabledNamespaces()).containsExactly(FIRST);
    }

    @Test
    public void canDisableMultipleNamespaces() {
        disabledNamespaces.disable(FIRST);
        disabledNamespaces.disable(SECOND);

        assertThat(disabledNamespaces.isDisabled(FIRST)).isTrue();
        assertThat(disabledNamespaces.isDisabled(SECOND)).isTrue();
        assertThat(disabledNamespaces.disabledNamespaces()).containsExactlyInAnyOrder(FIRST, SECOND);
    }

    @Test
    public void canReenableNamespaces() {
        disabledNamespaces.disable(FIRST);
        disabledNamespaces.disable(SECOND);
        disabledNamespaces.reenable(FIRST);

        assertThat(disabledNamespaces.isDisabled(FIRST)).isFalse();
        assertThat(disabledNamespaces.isDisabled(SECOND)).isTrue();
        assertThat(disabledNamespaces.disabledNamespaces()).containsExactly(SECOND);

        disabledNamespaces.reenable(SECOND);
        assertThat(disabledNamespaces.isDisabled(SECOND)).isFalse();
        assertThat(disabledNamespaces.disabledNamespaces()).isEmpty();
    }

    @Test
    public void disablingAndReenablingAreIdempotent() {
        disabledNamespaces.disable(FIRST);
        disabledNamespaces.disable(FIRST);
        disabledNamespaces.disable(FIRST);

        assertThat(disabledNamespaces.isDisabled(FIRST)).isTrue();

        disabledNamespaces.reenable(FIRST);
        disabledNamespaces.reenable(FIRST);
        assertThat(disabledNamespaces.isDisabled(FIRST)).isFalse();
    }
}
