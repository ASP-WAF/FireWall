using Microsoft.VisualStudio.TestTools.UnitTesting;
using Walter.Web.FireWall.Geo.IP2Loaction.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Walter.Web.FireWall.Geo.IP2Loaction.Models;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using Moq;
using Walter.BOM.Geo;

namespace Walter.Web.FireWall.Geo.IP2Loaction.Infrastructure.Tests
{
    [TestClass()]
    public class IP2LocationGeoFactoryTests
    {

        const string sampleJson= "{\"country_code\": \"CA\", \"credits_consumed\": 1}";

        [TestMethod()]
        public void QueryJsonTest()
        {
            var data =JsonConvert.DeserializeObject<Ip2LocationCoutyRequest>(sampleJson);
            Assert.AreEqual("CA", data.CountryCode,$"expect CA got {data.CountryCode}");
            Assert.AreEqual(1,data.CreditsUsed, $"expect 1, got {data.CreditsUsed}");


        }

        [TestMethod()]
        public void MapLocation2CountryTest()
        {
            var forTest = IFireWallConfig.CreateForUnitTest();


            using var service = new ServiceCollection()
                          .AddLogging()
                          .AddMemoryCache()
                          .AddSingleton<IFireWallConfig>(forTest)
                          .AddSingleton<IP2LocationGeoFactory>()
                          .BuildServiceProvider();

            var sud= service.GetRequiredService<IP2LocationGeoFactory>();
            var location =sud.MapLocation2Country(sampleJson);
        }


        [TestMethod()]
        public void QueryLocationTest()
        {    
            var forTest = IFireWallConfig.CreateForUnitTest();
            using var service = new ServiceCollection()
                          .AddLogging()
                          .AddMemoryCache()
                          .AddSingleton<IFireWallConfig>(forTest)
                          .AddSingleton<IGeoFactory, IP2LocationGeoFactory>()
                          .BuildServiceProvider();

            var sud= service.GetRequiredService<IGeoFactory>();
            var location =sud.QueryLocation(IPAddress.Parse("142.113.220.31"));
            Assert.AreEqual(Walter.BOM.Geo.GeoLocation.Canada, location);
        }

        [TestMethod()]
        public void IsGeoBlockedTest()
        {

            var forTest = IFireWallConfig.CreateForUnitTest();
            GeoBlockingPolicyBuilder builder = new GeoBlockingPolicyBuilder(forTest);
            builder.Block(Walter.BOM.Geo.GeoLocationMapping.NorthAmerica());
            builder.Build();

            using var service = new ServiceCollection()
                          .AddLogging()
                          .AddMemoryCache()
                          .AddSingleton<IFireWallConfig>(forTest)
                          .AddSingleton<IGeoFactory, IP2LocationGeoFactory>()
                          .BuildServiceProvider();

            var sud= service.GetRequiredService<IGeoFactory>();
            var location =sud.IsGeoBlocked(IPAddress.Parse("142.113.220.31"));
            Assert.AreEqual(true, location);
        }

        [TestMethod()]
        public void IsNotGeoBlockedTest()
        {

            var ip = IPAddress.Parse("142.113.220.31");
            var forTest = IFireWallConfig.CreateForUnitTest();
            GeoBlockingPolicyBuilder builder = new GeoBlockingPolicyBuilder(forTest);
            builder.Block(Walter.BOM.Geo.GeoLocationMapping.NorthAmerica());
            builder.Build();
            forTest.Geography.GeoExclusions.Add(new GeoFreeAccess(ip, GeoFreeAccessReason.Server));
            
            using var service = new ServiceCollection()
                          .AddLogging()
                          .AddMemoryCache()
                          .AddSingleton<IFireWallConfig>(forTest)
                          .AddSingleton<IGeoFactory, IP2LocationGeoFactory>()
                          .BuildServiceProvider();

            var sud= service.GetRequiredService<IGeoFactory>();
            var location =sud.IsGeoBlocked(ip);
            Assert.AreEqual(false, location);
        }


        [TestMethod()]
        public void IsBlockedTest()
        {
            var forTest = IFireWallConfig.CreateForUnitTest();
            GeoBlockingPolicyBuilder builder = new GeoBlockingPolicyBuilder(forTest);
            builder.Block(Walter.BOM.Geo.GeoLocationMapping.SupportedCountries());
            builder.Allow(new[] { GeoLocation.EUROPEAN_UNION });
            builder.Build();

            

            using var service = new ServiceCollection()
                          .AddLogging()
                          .AddMemoryCache()
                          .AddSingleton<IFireWallConfig>(forTest)
                          .AddSingleton<IGeoFactory, IP2LocationGeoFactory>()
                          .BuildServiceProvider();

            var sud = service.GetRequiredService<IGeoFactory>();
            var location = sud.IsBlocked(GeoLocation.Canada);
            Assert.AreEqual(true, location);
        }
        
        [TestMethod()]
        public void IsNotBlockedTest()
        {
            var forTest = IFireWallConfig.CreateForUnitTest();
            GeoBlockingPolicyBuilder builder = new GeoBlockingPolicyBuilder(forTest);
            builder.Block(Walter.BOM.Geo.GeoLocationMapping.SupportedCountries());
            builder.Allow(new[] { GeoLocation.EUROPEAN_UNION,GeoLocation.Canada });
            builder.Build();

            

            using var service = new ServiceCollection()
                          .AddLogging()
                          .AddMemoryCache()
                          .AddSingleton<IFireWallConfig>(forTest)
                          .AddSingleton<IGeoFactory, IP2LocationGeoFactory>()
                          .BuildServiceProvider();

            var sud = service.GetRequiredService<IGeoFactory>();
            var location = sud.IsBlocked(GeoLocation.Luxembourg);
            Assert.AreEqual(false, location);
        }



    }
}