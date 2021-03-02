using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json.Serialization;
using System;
using Walter.BOM.Geo;
using Walter.Web.FireWall.Geo.IP2Loaction.Infrastructure;

namespace Walter.Web.FireWall.Geo.IP2Loaction
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            DBHelper.CreateDatabases(false, Configuration, "fireWallStateIP2Location");

        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            //disable CORS as we will protect using the firewall and this only protects from browser based attacks
            services.AddCors(cors => cors.AddPolicy("AllowOrigin", option => option.AllowAnyOrigin()
                                                                                      .AllowAnyMethod()
                                                                                      .AllowAnyHeader()));

            services.AddLogging();
            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
                options.ConsentCookie.Name = "GDPR";
            });
            services.AddSession(conf =>
            {
                conf.Cookie.IsEssential = true;
                conf.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
                conf.Cookie.Name = "PHPSession";
                conf.IdleTimeout = TimeSpan.FromMinutes(20);
            });

            services.AddMemoryCache();
            services.AddAntiforgery();

            //register the custom IGeoFactory registration for the firewall to make use of
            services.AddSingleton<IGeoFactory, IP2LocationGeoFactory>();

            //register the firewall by injecting it 
            services.AddFireWall<MyFireWall>(FireWallTrial.License, FireWallTrial.DomainKey
                , domainName: new Uri("https://TrailDomain.com", UriKind.Absolute), options =>
               {
                   options.JoinCustomerImprovementProgramWithEmail = "w230769@outlook.com";
                   options.Cypher.ApplicationPassword = "123456Seven".AsMD5Hash();
                   options.ApplicationName = "www.test.dll";
                   options.ApplicationTag = "WS3";
                   options.UseSession = false;
                   options.FireWallMode = Walter.Web.FireWall.FireWallProtectionModes.WebSiteWithApi;



                   options.Cashing.GeoLocation.SlidingExpiration = TimeSpan.FromMinutes(20);

                   options.WebServices.UserEndpointJavaScript = new Uri(Walter.Web.FireWall.DefaultEndpoints.DefaultLinks.UserEndpointJavaScript, UriKind.Relative);
                   options.WebServices.IsUserApiUrl = new Uri(Walter.Web.FireWall.DefaultEndpoints.DefaultLinks.IsUserEndpoint, UriKind.Relative);
                   options.WebServices.RegisterLinksApiUrl = new Uri(Walter.Web.FireWall.DefaultEndpoints.DefaultLinks.SiteMapEndPoint, UriKind.Relative);
                   options.WebServices.BeaconApiUrl = new Uri(Walter.Web.FireWall.DefaultEndpoints.DefaultLinks.BeaconPoint, UriKind.Relative);
                   options.WebServices.CSPReportUrl = new Uri(Walter.Web.FireWall.DefaultEndpoints.DefaultLinks.CSPViolation, UriKind.Relative);

                   ///used in firewall status reports and reporting
                   options.ContactDetails.Address = "IT support address";
                   options.ContactDetails.EMail = "support@mydomain.com";
                   options.ContactDetails.Name = "Company name";
                   options.ContactDetails.Phone = "+123 123 456 789";
                   options.ContactDetails.Country = GeoLocation.Andorra;


                   options.Rules.AllowWhiteListing = true;
                   options.Rules.PhysicalFileWallExcludeReasons = Walter.BOM.FirewallBlockReasons.ALL & ~Walter.BOM.FirewallBlockReasons.NoAccessFromRegion;
                   options.Rules.BlockRequest.BlockDuration.SlideExpiration = true;
                   options.Rules.BlockRequest.BlockDuration.Expires = TimeSpan.FromSeconds(60);

                   //allow access to resources from internal and trusted external website
                   options.Rules.AddTrustedCrossSiteDomains(new Uri("https://wwwGithub.com", UriKind.Absolute)
                                                                , new Uri("https://www.nuget.org", UriKind.Absolute));

                   options.Rules.Headers.AddDefaultSecurePolicy()
                                        .AddStrictTransportSecurityNoCache()
                                        .AddXssProtectionBlockAndReport()
                                        .AddContentSecurityPolicyButTrust(trustingSites: Walter.Web.FireWall.TrustingSites.Jquery | Walter.Web.FireWall.TrustingSites.Google
                                                  , allowInline: true
                                                  , framesPolicy: Walter.Web.FireWall.FramesPolicy.Self);



               }).UseDatabase(connectionString: Configuration.GetConnectionString("fireWallStateIP2Location"), schema: "firewall", dataRetention: TimeSpan.FromDays(365))
                .UseUserAgentDBStore(connectionString: Configuration.GetConnectionString("fireWallStateIP2Location"), schema: "agent");


            //make json serialization easier when dealing with web api calls
            services.AddControllersWithViews()
                .AddNewtonsoftJson(options =>
                {
                    options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
                    options.SerializerSettings.ContractResolver = new DefaultContractResolver();
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
