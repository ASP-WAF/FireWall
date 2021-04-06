using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
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

    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;

            //this helper is used in the sample to create the databases if they do not exists
            //in production you would normally not use this utility class or method.
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
            services.AddFireWall<MyFireWall>(FireWallTrial.License, FireWallTrial.DomainKey, new Uri("https://www.mydomain.com", UriKind.Absolute), options =>

            {
                //use nuget package default endpoints to enable firewall management dashboard, than use administration to manage it
                options.Administration.GenerateConnectFile = false;
                
                options.Cypher.ApplicationPassword = "The password is 5 x 5, but I will not say in what order!";
                options.UseSession = true;


                //set the default security rule engines to reflect that you have a website and API requests for JavaScripts and monitoring
                options.FireWallMode = FireWallProtectionModes.WebSiteWithApi;

                //configure the firewall endpoints used when user discovery is used for web applications that support JavaScript
                options.WebServices.IsUserApiUrl = new Uri(Links.IsUserEndpoint, UriKind.Relative);
                options.WebServices.RegisterLinksApiUrl = new Uri(Links.SiteMapEndPoint, UriKind.Relative);
                options.WebServices.BeaconApiUrl = new Uri(Links.BeaconPoint, UriKind.Relative);
                options.WebServices.CSPReportUrl = new Uri(Links.CSP, UriKind.Relative);


                //tell the duration a malicious user is to be blocked
                options.Rules.BlockRequest.BlockDuration.Expires = TimeSpan.FromMinutes(5);
                options.Rules.BlockRequest.BlockDuration.SlideExpiration = true;

                //you can set the log levels for incident detection as well as firewall guard actions
                //manually. The namespace for the logger is at Walter.Web.FireWall.Guard 
                options.Rules.IncidentLogLevel = LogLevel.Information;
                options.Rules.GuardActionLogLevel = LogLevel.Warning;

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
             //use email reporting send emails 1x per day
             .UseSMTPReportingDatabase(connectionString: Configuration.GetConnectionString("FireWallState"), options => {
                    //keep mails for 60 days
                    options.Archive = TimeSpan.FromDays(60);                    
                    //template subject line will replace domain name with the actual domain name
                    options.Subject = "{Domain} incident report";
                    //smtp settings
                    options.From = "noreply@mydomain.com";
                    options.IgnoreServerCertificateErrors = true;
                    options.Server = "mail.mydomain.com";
                    options.Port = 8844;                   
                    options.UserName = "mailUserName";
                    options.Password = "mail password";
                    options.UseSsl = true;
                    //receivers of the reports as well as specify what reports to send
                    options.MailingList.Add(new EMailAddress("Admin", "admin@mydomain.com"){ 
                                    Frequency = TimeSpan.FromDays(1), 
                                    Roles = EMailRoles.SecurityRelevant }
                                    );
                    options.MailingList.Add(new EMailAddress("DEV", "developers@mydomain.com"){ 
                                    Frequency = TimeSpan.FromDays(1), 
                                    Roles = EMailRoles.ProductUpdates }
                                    );

                    });

            //configure the firewall to be active on each request by registering the firewall filter
            services.AddMvc(setupAction =>
            {
                //inform the browser of our privacy policy if you render views                
                setupAction.Filters.Add<Walter.Web.FireWall.Filters.PrivacyPreferencesFilter>();
                //view the filter documentation at https://firewallapi.asp-waf.com/?topic=html/N-Walter.Web.FireWall.Filters.htm

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
