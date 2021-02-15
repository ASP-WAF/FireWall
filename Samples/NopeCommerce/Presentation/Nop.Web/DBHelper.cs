using Microsoft.Extensions.Configuration;
using System.Data.SqlClient;

namespace Nop.Web
{
    class DBHelper
    {

        /// <summary>
        /// Creates the databases.
        /// </summary>
        /// <param name="blank">if set to <c>true</c> [blank] databases will be use.</param>
        /// <param name="configuration">The configuration to use.</param>
        /// <param name="names">The connection string names to use.</param>
        public static void CreateDatabases(bool blank, IConfiguration configuration, params string[] names)
        {
            foreach (var name in names)
            {
                if (blank)
                {
                    DropAndCreate(connectionString: configuration.GetConnectionString(name));
                }
                else
                {
                    MakeSureExists(connectionString: configuration.GetConnectionString(name));
                }
            }
        }

        private static void MakeSureExists(string connectionString)
        {
            var cb = new SqlConnectionStringBuilder(connectionString);
            var databaseName = cb.InitialCatalog;
            cb.InitialCatalog = "Master";
            using (var conn = new SqlConnection(cb.ToString()))
            {
                conn.Open();

                var cmd = new SqlCommand
                {
                    Connection = conn,
                    CommandType = System.Data.CommandType.Text,
                    CommandText = string.Format(@"
IF NOT EXISTS(SELECT * FROM sys.databases WHERE name='{0}')
BEGIN
  DECLARE @FILENAME AS VARCHAR(255)
  SET @FILENAME = CONVERT(VARCHAR(255), SERVERPROPERTY('instancedefaultdatapath')) + '{0}';
  EXEC ('CREATE DATABASE [{0}] ON PRIMARY (NAME = [{0}], FILENAME =''' + @FILENAME + ''', SIZE = 25MB, MAXSIZE = 50MB, 	FILEGROWTH = 5MB )');
END",
                databaseName)
                };

                cmd.ExecuteNonQuery();
            }
        }
        private static void DropAndCreate(string connectionString)
        {
            var cb = new SqlConnectionStringBuilder(connectionString);
            var databaseName = cb.InitialCatalog;
            cb.InitialCatalog = "Master";
            using (var conn = new SqlConnection(cb.ToString()))
            {
                conn.Open();

                var cmd = new SqlCommand
                {
                    Connection = conn,
                    CommandType = System.Data.CommandType.Text,
                    CommandText = string.Format(@"
IF EXISTS(SELECT * FROM sys.databases WHERE name='{0}')
	BEGIN
		ALTER DATABASE [{0}]
		SET SINGLE_USER
		WITH ROLLBACK IMMEDIATE
		DROP DATABASE [{0}]
	END
	DECLARE @FILENAME AS VARCHAR(255)
	SET @FILENAME = CONVERT(VARCHAR(255), SERVERPROPERTY('instancedefaultdatapath')) + '{0}';
	EXEC ('CREATE DATABASE [{0}] ON PRIMARY 
		(NAME = [{0}], 
		FILENAME =''' + @FILENAME + ''', 
		SIZE = 25MB, 
		MAXSIZE = 50MB, 
		FILEGROWTH = 5MB )')",
    databaseName)
                };

                cmd.ExecuteNonQuery();
            }
        }

    }
}