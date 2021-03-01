# About this GEO sample
This sample demonstrates how to implement GeoBlocking as well as make use of the FireWall’s TagHelpers

## Sample code
Have a look at the tests located in [IP2LocationGeoFactoryTests.cs ](https://github.com/ASP-WAF/FireWall/blob/master/Samples/IGeoFactory%20implementation/Walter.Web.FireWall.Geo.IP2LoactionTests/Infrastructure/IP2LocationGeoFactoryTests.cs)
and navigate to the test method
````C#
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
````        

This file shows several ways you can test the firewall as well as inject your own GEO resolver
