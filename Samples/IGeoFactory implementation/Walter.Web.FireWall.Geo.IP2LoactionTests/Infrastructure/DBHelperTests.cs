using Microsoft.VisualStudio.TestTools.UnitTesting;
using Walter.Web.FireWall.Geo.IP2Loaction.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace Walter.Web.FireWall.Geo.IP2Loaction.Infrastructure.Tests
{
    [TestClass()]
    public class DBHelperTests
    {
        [TestMethod()]
        public void CreateDatabasesTest()
        {
            var configuration = new ConfigurationBuilder()
                                .AddJsonFile("testAppsettings.json")
                                .Build();
            var names = configuration.GetAllConnectionStringsNames();
            Assert.AreEqual(3, names.Length);

        }
    }
}