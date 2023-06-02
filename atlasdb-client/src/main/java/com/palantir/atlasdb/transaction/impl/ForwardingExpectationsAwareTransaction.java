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

package com.palantir.atlasdb.transaction.impl;

import com.palantir.atlasdb.transaction.api.expectations.TransactionCommitLockInfo;
import com.palantir.atlasdb.transaction.api.expectations.TransactionReadInfo;

public abstract class ForwardingExpectationsAwareTransaction extends ForwardingTransaction
        implements ExpectationsAwareTransaction {

    @Override
    public abstract ExpectationsAwareTransaction delegate();

    @Override
    public long getAgeMillis() {
        return delegate().getAgeMillis();
    }

    @Override
    public TransactionReadInfo getReadInfo() {
        return delegate().getReadInfo();
    }

    @Override
    public TransactionCommitLockInfo getCommitLockInfo() {
        return delegate().getCommitLockInfo();
    }

    @Override
    public void reportExpectationsCollectedData() {
        delegate().reportExpectationsCollectedData();
    }
}
