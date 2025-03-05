--[[
Rule name: SQL error detection
Filtering stage: Response body
Threat level: High
Rule description: SQL errors returning to the page may leak sensitive server information
--]]


local check = waf.plugins.sqlErrorDetection.check
local rb = waf.respBody
local rgx = waf.rgxMatch
local has = waf.contains

if waf.status == 500 then
    local m = check(rb)
    if m then
        if rgx(rb, "JET Database Engine|Access Database Engine|\\[Microsoft\\]\\[ODBC Microsoft Access Driver\\]", "jo") then
            return m, "Microsoft Access SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "ORA-[0-9][0-9][0-9][0-9]|java\\.sql\\.SQLException|Oracle error|Oracle.*Driver|Warning.*oci_.*|Warning.*ora_.*", "jo") then
            return m, "Oracle SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "DB2 SQL error:|\\[IBM\\]\\[CLI Driver\\]\\[DB2/6000\\]|CLI Driver.*DB2|DB2 SQL error|db2_\\w+\\(", "jo") then
            return m, "DB2 SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "\\[DM_QUERY_E_SYNTAX\\]|has occurred in the vicinity of:", "jo") then
            return m, "EMC SQL Information Leakage: " .. rb, true
        end
        if has(rb, "Dynamic SQL Error") then
            return m, "firebird SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "Exception (?:condition )?\\d+\\. Transaction rollback\\.", "jo") then
            return m, "Frontbase SQL Information Leakage: " .. rb, true
        end
        if has(rb, "org.hsqldb.jdbc") then
            return m, "hsqldb SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "An illegal character has been found in the statement|com\\.informix\\.jdbc|Exception.*Informix", "jo") then
            return m, "informix SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "Warning.*ingres_|Ingres SQLSTATE|Ingres\\W.*Driver", "jo") then
            return m, "ingres SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "<b>Warning</b>: ibase_|Unexpected end of command in statement", "jo") then
            return m, "interbase SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "SQL error.*POS[0-9]+|Warning.*maxdb", "jo") then
            return m, "maxDB SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "System\\.Data\\.OleDb\\.OleDbException|\\[Microsoft\\]\\[ODBC SQL Server Driver\\]|\\[Macromedia\\]\\[SQLServer JDBC Driver\\]|\\[SqlException|System\\.Data\\.SqlClient\\.SqlException|Unclosed quotation mark after the character string|'80040e14'|mssql_query\\(\\)|Microsoft OLE DB Provider for ODBC Drivers|Microsoft OLE DB Provider for SQL Server|Incorrect syntax near|Sintaxis incorrecta cerca de|Syntax error in string in query expression|Procedure or function .* expects parameter|Unclosed quotation mark before the character string|Syntax error .* in query expression|Data type mismatch in criteria expression\\.|ADODB\\.Field \\(0x800A0BCD\\)|the used select statements have different number of columns|OLE DB.*SQL Server|Warning.*mssql_.*|Driver.*SQL[ _-]*Server|SQL Server.*Driver|SQL Server.*[0-9a-fA-F]{8}|Exception.*\\WSystem\\.Data\\.SqlClient\\.", "jo") then
            return m, "Mssql SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "MyS(?:QL server version for the right syntax to use|qlClient\\.)|(?:supplied argument is not a valid |SQL syntax.*)MySQL|Column count doesn't match(?: value count at row)?|(?:Table '[^']+' doesn't exis|valid MySQL resul)t|You have an error in your SQL syntax(?: near|;)|Warning.{1,10}mysql_(?:[a-z_()]{1,26})?|ERROR [0-9]{4} \\([a-z0-9]{5}\\):|mysql_fetch_array\\(\\)|on MySQL result index|\\[MySQL\\]\\[ODBC", "jo") then
            return m, "Mysql SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "PostgreSQL query failed:|pg_query\\(\\) \\[:|pg_exec\\(\\) \\[:|PostgreSQL.{1,20}ERROR|Warning.*\\bpg_.*|valid PostgreSQL result|Npgsql\\.|PG::[a-zA-Z]*Error|Supplied argument is not a valid PostgreSQL .*? resource|Unable to connect to PostgreSQL server", "jo") then
            return m, "Postgres SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "Warning.*sqlite_|Warning.*SQLite3::|SQLite/JDBCDriver|SQLite\\.Exception|System\\.Data\\.SQLite\\.SQLiteException", "jo") then
            return m, "SQLite SQL Information Leakage: " .. rb, true
        end
        if rgx(rb, "Sybase message:|Warning.{2,20}sybase|Sybase.*Server message", "jo") then
            return m, "Sybase SQL Information Leakage: " .. rb, true
        end
    end
end

return false