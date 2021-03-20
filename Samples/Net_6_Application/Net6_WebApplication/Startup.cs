using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Net6_WebApplication.Infrastructure;
using System;
using System.Reflection;
using Walter.Web.FireWall;

namespace Net6_WebApplication
{
    public static class Links
    {
        public const string CSPViolation = "api/CSP";
        public const string SiteMapEndPoint = "api/SiteMap";
        public const string IsUserEndpoint = "api/UserDiscovery";
        public const string BeaconPoint = "api/Beacon";
        public const string UserEndpointJavaScript = "~/js/site2.js";

    }
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            DBHelper.CreateDatabases(false, Configuration, "fireWallStateNet6");
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMemoryCache();
            services.AddLogging();

            services.AddFireWall(FireWallTrial.License
                            , FireWallTrial.DomainKey
                            , domainName: new Uri("https://www.Net6-demo.dll", UriKind.Absolute), options =>
                            {
                                //set your options you need, there are several options like rules and reporting there are however 2 key properties 

                                //1. tell the firewall that your not using session storage (important when load balancing the site)
                                options.UseSession = false;

                                //2. tell the firewall the rule engine to load
                                options.FireWallMode = FireWallProtectionModes.WebSiteWithApi;

                                options.WebServices.UserEndpointJavaScript = new Uri(Links.UserEndpointJavaScript, UriKind.Relative);
                                options.WebServices.IsUserApiUrl = new Uri(Links.IsUserEndpoint, UriKind.Relative);
                                options.WebServices.RegisterLinksApiUrl = new Uri(Links.SiteMapEndPoint, UriKind.Relative);
                                options.WebServices.BeaconApiUrl = new Uri(Links.BeaconPoint, UriKind.Relative);
                                options.WebServices.CSPReportUrl = new Uri(Links.CSPViolation, UriKind.Relative);

                                //3. if you create your own custom class that derives from 
                                //  ControllerBase
                                //  Controller
                                //  RazorPage
                                // then register it in 
                                //options.ProtectedTypes.Add(typeof(MyOwnBaseController));

                            })//you do not need a firewall database for state storage but it does perform paster and you can retain data longer
                            .UseDatabase(connectionString: Configuration.GetConnectionString("fireWallStateNet6")
                                        , schema: "dbo", dataRetention: TimeSpan.FromDays(365));

            // minimal protection
            services.AddMvc(options =>
            {
                // set the firewall to respond to all requests, the lower the order the earlier the detection
                options.Filters.Add<Walter.Web.FireWall.Filters.FireWallFilter>(0);
            });

            services.AddControllersWithViews();
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
