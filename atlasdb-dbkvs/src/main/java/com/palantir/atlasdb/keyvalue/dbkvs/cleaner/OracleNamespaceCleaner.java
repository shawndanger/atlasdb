/*
 * (c) Copyright 2022 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.atlasdb.keyvalue.dbkvs.cleaner;

import com.palantir.atlasdb.NamespaceCleaner;
import com.palantir.atlasdb.keyvalue.dbkvs.DbKeyValueServiceConfig;
import com.palantir.atlasdb.keyvalue.dbkvs.OracleDdlConfig;
import com.palantir.common.base.FunctionCheckedException;
import com.palantir.nexus.db.pool.ConnectionManager;
import com.palantir.nexus.db.pool.HikariClientPoolConnectionManagers;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class OracleNamespaceCleaner implements NamespaceCleaner {
    private static final String LIST_ALL_TABLES =
            "SELECT table_name FROM all_tables WHERE owner = ? AND table_name LIKE ?";
    private static final String DROP_TABLE = "DROP TABLE %s"; // not CASCADE CONSTRAINTS NOR PURGE
    private OracleDdlConfig oracleDdlConfig;
    private final DbKeyValueServiceConfig config;

    private final ConnectionManager connectionManager;

    public OracleNamespaceCleaner(OracleDdlConfig oracleDdlConfig, DbKeyValueServiceConfig config) {
        this.oracleDdlConfig = oracleDdlConfig;
        this.config = config;
        this.connectionManager = HikariClientPoolConnectionManagers.createShared(config.connection(), 1, 30);
    }

    @Override
    public void dropAllTables() {
        runWithConnection(connection -> {
            PreparedStatement dropTablePreparedStatement = connection.prepareStatement(DROP_TABLE);
            PreparedStatement listAllTablesPreparedStatement = connection.prepareStatement(LIST_ALL_TABLES);

            dropAllTablesFromList(
                    dropTablePreparedStatement,
                    getAllTablesWithPrefix(listAllTablesPreparedStatement, oracleDdlConfig.tablePrefix()));

            dropAllTablesFromList(
                    dropTablePreparedStatement,
                    getAllTablesWithPrefix(listAllTablesPreparedStatement, oracleDdlConfig.overflowTablePrefix()));
            return null;
        });
    }

    @Override
    public boolean areAllTablesSuccessfullyDropped() {
        return runWithConnection(connection -> {
            PreparedStatement listAllTablesPreparedStatement = connection.prepareStatement(LIST_ALL_TABLES);
            return getAllTablesWithPrefix(listAllTablesPreparedStatement, oracleDdlConfig.tablePrefix())
                            .isBeforeFirst()
                    && getAllTablesWithPrefix(listAllTablesPreparedStatement, oracleDdlConfig.overflowTablePrefix())
                            .isBeforeFirst();
        });
    }

    private ResultSet getAllTablesWithPrefix(PreparedStatement listAllTablesPreparedStatement, String prefix)
            throws SQLException {
        listAllTablesPreparedStatement.setString(
                1, withWildcardSuffix(config.connection().getDbLogin()));
        listAllTablesPreparedStatement.setString(2, withWildcardSuffix(prefix));
        ResultSet resultSet = listAllTablesPreparedStatement.executeQuery();
        listAllTablesPreparedStatement.clearParameters();
        return resultSet;
    }

    private void dropAllTablesFromList(Statement statement, ResultSet tableNames) throws SQLException {
        while (tableNames.next()) {
            String tableName = tableNames.getString("table_name");
            statement.executeUpdate(String.format(DROP_TABLE, tableName));
            // There is no IF EXISTS. DDL commands perform an implicit commit. If we fail, we should just retry by
            // dropping the namespace again!
        }
    }

    private <T> T runWithConnection(FunctionCheckedException<Connection, T, SQLException> task) {
        try (Connection connection = connectionManager.getConnection()) {
            return task.apply(connection);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private static String withWildcardSuffix(String tableName) {
        return tableName + "%";
    }

    @Override
    public void close() throws IOException {
        try {
            connectionManager.close();
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }
}
