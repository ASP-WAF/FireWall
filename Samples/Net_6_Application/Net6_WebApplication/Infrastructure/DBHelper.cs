using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Net6_WebApplication.Infrastructure
{
    public static class DBHelper
    {


        /// <summary>
        /// Creates the databases for the Nope demo application.
        /// </summary>
        /// <param name="blank">if set to <c>true</c> [blank] databases will be use.</param>
        /// <param name="configuration">The configuration to use.</param>
        /// <param name="names">The named connection string to use from the IConfiguration, leave blank to do all.</param>
        public static void CreateDatabases(bool blank, IConfiguration configuration, params string[] names)
        {
            if (configuration is null)
            {
                throw new System.ArgumentNullException(nameof(configuration));
            }

            if (names.Length == 0)
            {
                names = configuration.GetAllConnectionStringsNames();
            }

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


        /// <summary>
        /// helper method 
        /// </summary>
        /// <param name="configuration"></param>
        /// <returns></returns>
        public static string[] GetAllConnectionStringsNames(this IConfiguration configuration)
        {
            return configuration.GetSection("ConnectionStrings")
                                         .GetChildren()
                                         .Select(s => s.Key)
                                         .ToArray();
        }

        /// <summary>
        /// Make sure that the database exists, create if missing
        /// </summary>
        /// <param name="connectionString">the connection string to use</param>
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

        /// <summary>
        /// Drop and re-create the database if exists, else just create it
        /// </summary>
        /// <remarks>
        /// This is likely only useful during development
        /// </remarks>
        /// <param name="connectionString">the connection string to use</param>
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
