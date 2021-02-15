using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using MVC_Core_31_Application.Infrastructure;
using System;
using System.Net;
using Walter.Web.FireWall;
using Walter.Web.FireWall.Destinations.Email;

namespace MVC_Core_31_Application
{

    /// <summary>
    /// this class is used to match the routs needed to communicate data back to the firewall
    /// </summary>
    /// <remarks>
    /// This technique allows you to implement your own naming convention in the MVC pattern
    /// See the UserDiscoveryController and the service configuration for a demonstration how the data is linked and used
    /// </remarks>
    public static class Links
    {
        /// <summary>
        /// registers the links the user would have access to when he visits a page
        /// </summary>
        public const string SiteMapEndPoint = "api/SiteMap";
        /// <summary>
        /// Is used by the build-in script to communicate user discovery data
        /// </summary>
        public const string IsUserEndpoint = "api/UserDiscovery";
        /// <summary>
        /// is used to inform the browser to send beacon data when a user leaves a page
        /// </summary>
        public const string BeaconPoint = "api/Beacon";
        /// <summary>
        /// is used by the browser to send CSP violations for reporting
        /// </summary>
        public const string CSP = "api/CSP";
        /// <summary>
        /// Is integrated in the _layout.cshtml and is used to inject the FireWall scrip in to each page
        /// </summary>
        /// <remarks>You should have 3 references to this constant
        /// 1. in the firewall configuration using:
        ///    options.WebServices.IsUserApiUrl = new Uri(Links.IsUserEndpoint, UriKind.Relative);
        ///    
        /// 2. in the rout template of a controller using:
        ///    [Route(Links.UserEndpointJavaScript)]
        ///    
        /// 3. in the _layout.cshtml linking the template to the FileResult using:
        ///    <script src="@Url.Content(MVC_Core_31_Application.Links.UserEndpointJavaScript)"></script>
        /// </remarks>
        public const string UserEndpointJavaScript = "~/js/jquery.legasy.js";
    }


    class DBHelper
    {

        /// <summary>
        /// Creates the databases.
        /// </summary>
        /// <param name="blank">if set to <c>true</c> [blank] databases will be use.</param>
        /// <param name="configuration">The configuration to use.</param>
        /// <param name="names">The connection string names to use.</param>
        public static void CreateDatabases(bool blanq, IConfiguration configuration,params string[] names)
        {
            foreach (var name in names)
            {
                if (blanq)
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
                    CommandType= System.Data.CommandType.Text,
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



    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            DBHelper.CreateDatabases(false, Configuration, "FireWallState", "FireWallMail");
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddLogging(configure =>
            {
                configure.AddConsole();
                configure.SetMinimumLevel(LogLevel.Information);
            });


            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
                options.ConsentCookie.Name = "GDPR";
            });

            /*Change the default AF token names in your forms to something that is valid as well as unique to your site
            *
            * Altering the AF definition is "camouflage" as well as adds an active layer of protection that the firewall
            *  will generate a rule for and discover attack vectors like cookie poisoning as well as Host header attacks
            *  that may be used for web cache poisoning and attacks such as password reset poisoning. Web cache 
            *  poisoning lets an attacker serve poisoned content to anyone who requests pages. Using password 
            *  reset poisoning, the attacker can obtain a password reset token and reset another user's password. 
            */
            services.AddAntiforgery(options =>
            {
                options.Cookie.Name = "X-XSRF-TOKEN";
                options.HeaderName = "X-XSRF-TOKEN";
                options.FormFieldName = "__XSRF";
            });

            /*
             * Change the default cookie name for session so that bots think you are using PHP
             * Cookie definition is "camouflage" as well as adds an active layer of protection
             * and discover attack vectors like cookie poisoning
             */
            services.AddSession(option =>
            {
                option.Cookie.Name = "PHPSESSID";
                option.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                option.Cookie.SameSite = SameSiteMode.Strict;
                option.Cookie.HttpOnly = true;
                option.IdleTimeout = TimeSpan.FromMinutes(20);
                option.IOTimeout = TimeSpan.FromSeconds(2);
            });

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
            services.AddFireWall<MyFireWall>(FireWallTrail.License, FireWallTrail.DomainKey, new Uri("https://www.mydomain.com", UriKind.Absolute), options =>

            {
               
                //set your public IP address when debugging so you can simulate IP based protection     
                //your real public IP address is accessible at  Walter.Net.Networking.RuntimeValues.PublicIpAddress 
                options.PublicIpAddress = IPAddress.Parse("8.8.8.4");

        
                options.Cypher.ApplicationPassword = "The password is 5 x 5, but I will not say in what order!";
                options.UseSession = true;


                //set the default security rule engines to reflect that you have a website and API requests for JavaScripts and monitoring
                options.FireWallMode =FireWallProtectionModes.WebSiteWithApi;

                //configure the firewall endpoints used when user discovery is used for web applications that support JavaScript
                options.WebServices.IsUserApiUrl = new Uri(Links.IsUserEndpoint, UriKind.Relative);
                options.WebServices.RegisterLinksApiUrl = new Uri(Links.SiteMapEndPoint, UriKind.Relative);
                options.WebServices.BeaconApiUrl = new Uri(Links.BeaconPoint, UriKind.Relative);
                options.WebServices.CSPReportUrl = new Uri(Links.CSP, UriKind.Relative);


                //tell the duration a malicious user is to be blocked
                options.Rules.BlockRequest.BlockDuration.Expires = TimeSpan.FromMinutes(5);
                options.Rules.BlockRequest.BlockDuration.SlideExpiration = true;

                //set the rules for browser based protection, the firewall can do without them but the extra layer of defense does not hurt
                //having set the rules also helps the firewall understand your intend and help sniff-out bots that are violating the rules that
                //the browser would have detected and rejected. Header protection is "camouflage" as well as adds an active layer of protection
                options.Rules.Headers.AddDefaultSecurePolicy()
                                     .AddFrameOptionsDeny()
                                     .AddStrictTransportSecurityNoCache()
                                     .DoNotTrack()
                                     .SimulateDifferentServer(Walter.Web.FireWall.Headers.ServerSimulation.Apache249Unix)
                                     .SimulateDifferentTechnologyStack(Walter.Web.FireWall.Headers.StackSimulation.PHP)
                                     .AddXssProtectionBlockAndReport(Links.CSP)
                                     .AddContentSecurityPolicyTrustOnlySelf();


            })//store firewall state in a database making the firewall faster and allow it for the firewall to maintain large data volumes
                .UseDatabase(connectionString: Configuration.GetConnectionString("FireWallState"), schema: "dbo", dataRetention: TimeSpan.FromDays(90))
              //use different delta for email frequency where the firewall will collect and bundle incidents and issues in a single mail
                .UseSMTPReportingDatabase(connectionString: Configuration.GetConnectionString("FireWallMail"), options =>
                {
                    options.Archive = TimeSpan.FromDays(365);
                    options.Server = "mail.mydomain.com";
                    options.UserName = "noreply@mydomain.com";
                    options.Password = "SmtP-pa$$w0rd-1234";
                    options.Port = 25;
                    options.From = "noreply@your-domain.com";
                    options.IgnoreServerCertificateErrors = true;
                    options.DefaultEmail = "webmaster@mydomain.com";
                    options.MailingList.AddRange(new[] {
                        new EMailAddress(displayName:"Security Administrators", address:"security@mydomain.com") {
                            Frequency = TimeSpan.FromHours(1),
                            Roles = EMailRoles.FireWallAdministrationViolations | EMailRoles.UnauthorizedPhysicalFilesViolation },
                        new EMailAddress(displayName:"Application developers", address:"info@mydomain.com") {
                            Frequency = TimeSpan.FromDays(1),
                            Roles = EMailRoles.ProductUpdates | EMailRoles.OwnAccountRelatedViolations },
                        });
                });

            services.AddMvc(setupAction =>
            {
                //enable the firewall on all endpoints in this application 
                setupAction.Filters.Add<Walter.Web.FireWall.Filters.FireWallFilter>();
                //inform the browser of our privacy policy
                setupAction.Filters.Add<Walter.Web.FireWall.Filters.PrivacyPreferencesFilter>();
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

            app.UseFireWall();

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
