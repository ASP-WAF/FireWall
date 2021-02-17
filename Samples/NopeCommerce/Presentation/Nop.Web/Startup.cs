using Autofac;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Nop.Core.Configuration;
using Nop.Core.Infrastructure;
using Nop.Web.Areas.Admin.Controllers;
using Nop.Web.Controllers;
using Nop.Web.Framework;
using Nop.Web.Framework.Infrastructure.Extensions;
using System;
using System.Net;
using Walter.Web.FireWall;

namespace Nop.Web
{
    internal static class Links
    {
        public const string SiteMapEndPoint = "api/SiteMap";
        public const string IsUserEndpoint = "api/UserDiscovery";
        public const string BeaconPoint = "api/Beacon";
        public const string CSP = "api/CSP";
        public const string UserEndpointJavaScript = "js/jquery.legasy.js";
    }

    /// <summary>
    /// Represents startup class of application
    /// </summary>
    public class Startup
    {
        #region Fields

        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private IEngine _engine;
        private NopConfig _nopConfig;

        #endregion

        #region Ctor

        public Startup(IConfiguration configuration, IWebHostEnvironment webHostEnvironment)
        {
            _configuration = configuration;
            _webHostEnvironment = webHostEnvironment;
            
            DBHelper.CreateDatabases(false, _configuration, "fireWallStateNope");
        }

        #endregion

        /// <summary>
        /// Add services to the application and configure service provider
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        public void ConfigureServices(IServiceCollection services)
        {
            (_engine, _nopConfig) = services.ConfigureApplicationServices(_configuration, _webHostEnvironment);



            /* Use memory cashing to speed up the application
             *  you can use plugins like Redis or SQL backed cashing if you are using fail-over servers
             *  when using cashing the discovered ISP data of those that are attacking you will be re-used
             *  and do not have to be re-discovered on each request.
             */
            services.AddMemoryCache();

            /*Inject the firewall with a given configuration in your application
             * You can use your own class and derive the firewall from that as a base class
             *  then you can tune the configuration options to reflect your preferences
             *  see online documentation for more information on the configuration options
             *  at https://firewallapi.asp-waf.com/?topic=html/AllMembers.T-Walter.Web.FireWall.IFireWallConfig.htm
             *  
             *  The sample configuration can also be stored and loaded in json configuration, perhaps make the configuration
             *  in code first and then save it as json to get started as the number of configuration options are abundant
             */
            services.AddFireWall<MyFireWall>(FireWallTrail.License, FireWallTrail.DomainKey
                , new Uri("https://www.mydomain.com", UriKind.Absolute), options =>

            {

                //set your public IP address when debugging so you can simulate IP based protection     
                //your real public IP address is accessible at  Walter.Net.Networking.RuntimeValues.PublicIpAddress 
                options.PublicIpAddress = IPAddress.Parse("8.8.8.4");


                options.Cypher.ApplicationPassword = "The password is 5 x 5, but I will not say in what order!"
                                                     .AsShaHash(HashMethod.SHA1,8);
                
                //data is stored in memory cash and not in session, use session if you might run low on memory
                options.UseSession = false;
                options.Cashing.TemporaryUsers.SlidingExpiration = TimeSpan.FromMinutes(20);
                options.Cashing.TemporaryUsers.Priority =  Microsoft.Extensions.Caching.Memory.CacheItemPriority.High;

                //set the default security rule engines to reflect that you have a website and API requests for JavaScripts and monitoring
                options.FireWallMode = FireWallProtectionModes.WebSiteWithApi;


                //tell the duration a malicious user is to be blocked
                options.Rules.BlockRequest.BlockDuration.Expires = TimeSpan.FromMinutes(5);
                options.Rules.BlockRequest.BlockDuration.SlideExpiration = true;

                options.ProtectedEndPointTypes.Add(typeof(BasePublicController));
                options.ProtectedEndPointTypes.Add(typeof(BaseAdminController));


                //you can set the log levels for incident detection as well as firewall guard actions
                //manually. The namespace for the logger is at Walter.Web.FireWall.Guard 
                options.Rules.IncidentLogLevel = Microsoft.Extensions.Logging.LogLevel.Information;
                options.Rules.GuardActionLogLevel = Microsoft.Extensions.Logging.LogLevel.Warning;


                //we make use of the build-in Java script to detect and validate user and user interactions
                options.WebServices.IsUserApiUrl = new Uri(Links.IsUserEndpoint, UriKind.Relative);
                options.WebServices.RegisterLinksApiUrl = new Uri(Links.SiteMapEndPoint, UriKind.Relative);
                options.WebServices.BeaconApiUrl = new Uri(Links.BeaconPoint, UriKind.Relative);
                options.WebServices.CSPReportUrl = new Uri(Links.CSP, UriKind.Relative);

                //set the rules for browser based protection, the firewall can do without them but the extra layer of defense does not hurt
                //having set the rules also helps the firewall understand your intend and help sniff-out bots that are violating the rules that
                //the browser would have detected and rejected. Header protection is "camouflage" as well as adds an active layer of protection
                options.Rules.Headers.AddDefaultSecurePolicy()
                                     .AddFrameOptionsDeny()
                                     .AddStrictTransportSecurityNoCache()
                                     .DoNotTrack()
                                     .SimulateDifferentServer(Walter.Web.FireWall.Headers.ServerSimulation.Apache249Unix)
                                     .SimulateDifferentTechnologyStack(Walter.Web.FireWall.Headers.StackSimulation.PHP)
                                     .AddXssProtectionBlockAndReport(Walter.Web.FireWall.DefaultEndpoints.DefaultLinks.CSPViolation)
                                     .AddContentSecurityPolicyTrustOnlySelf();


            })//store firewall state in a database making the firewall faster and allow it for the firewall to maintain large data volumes
                .UseDatabase(connectionString: _configuration.GetConnectionString("fireWallStateNope"), schema: "dbo", dataRetention: TimeSpan.FromDays(90));

        }

        public void ConfigureContainer(ContainerBuilder builder)
        {
            _engine.RegisterDependencies(builder, _nopConfig);
        }

        /// <summary>
        /// Configure the application HTTP request pipeline
        /// </summary>
        /// <param name="application">Builder for configuring an application's request pipeline</param>
        public void Configure(IApplicationBuilder application)
        {
            application.ConfigureRequestPipeline();

            application.StartEngine();

            //integrate the firewall
            application.UseFireWall();
        }
    }
}