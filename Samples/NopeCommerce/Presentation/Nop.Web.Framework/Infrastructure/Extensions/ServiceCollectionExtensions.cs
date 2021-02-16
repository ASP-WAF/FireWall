using System;
using System.Linq;
using System.Net;
using System.Reflection;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.Storage;
using Microsoft.Azure.Storage.Blob;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json.Serialization;
using Nop.Core;
using Nop.Core.Configuration;
using Nop.Core.Domain;
using Nop.Core.Domain.Common;
using Nop.Core.Http;
using Nop.Core.Infrastructure;
using Nop.Core.Redis;
using Nop.Core.Security;
using Nop.Data;
using Nop.Services.Authentication;
using Nop.Services.Authentication.External;
using Nop.Services.Common;
using Nop.Services.Security;
using Nop.Web.Framework.Mvc.ModelBinding;
using Nop.Web.Framework.Mvc.Routing;
using Nop.Web.Framework.Security.Captcha;
using Nop.Web.Framework.Themes;
using StackExchange.Profiling.Storage;
using Walter.Web.FireWall;
using WebMarkupMin.AspNetCore3;
using WebMarkupMin.NUglify;

namespace Nop.Web.Framework.Infrastructure.Extensions
{
    /// <summary>
    /// Represents extensions of IServiceCollection
    /// </summary>
    public static partial class ServiceCollectionExtensions
    {
        /// <summary>
        /// Add services to the application and configure service provider
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        /// <param name="configuration">Configuration of the application</param>
        /// <param name="webHostEnvironment">Hosting environment</param>
        /// <returns>Configured service provider</returns>
        public static (IEngine, NopConfig) ConfigureApplicationServices(this IServiceCollection services,
            IConfiguration configuration, IWebHostEnvironment webHostEnvironment)
        {
            //most of API providers require TLS 1.2 nowadays
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            //add NopConfig configuration parameters
            var nopConfig = services.ConfigureStartupConfig<NopConfig>(configuration.GetSection("Nop"));

            //add hosting configuration parameters
            services.ConfigureStartupConfig<HostingConfig>(configuration.GetSection("Hosting"));

            //add accessor to HttpContext
            services.AddHttpContextAccessor();

            DBHelper.CreateDatabases(false, configuration, "fireWallStateNope");

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


                options.Cypher.ApplicationPassword = "The password is 5 x 5, but I will not say in what order!";
                options.UseSession = true;


                //set the default security rule engines to reflect that you have a website and API requests for JavaScripts and monitoring
                options.FireWallMode = FireWallProtectionModes.WebSiteWithApi;


                //tell the duration a malicious user is to be blocked
                options.Rules.BlockRequest.BlockDuration.Expires = TimeSpan.FromMinutes(5);
                options.Rules.BlockRequest.BlockDuration.SlideExpiration = true;

                //you can set the log levels for incident detection as well as firewall guard actions
                //manually. The namespace for the logger is at Walter.Web.FireWall.Guard 
                options.Rules.IncidentLogLevel = Microsoft.Extensions.Logging.LogLevel.Information;
                options.Rules.GuardActionLogLevel = Microsoft.Extensions.Logging.LogLevel.Warning;


                options.WebServices.IsUserApiUrl = new Uri(Walter.Web.FireWall.DefaultEndpoints.DefaultLinks.IsUserEndpoint, UriKind.Relative);
                options.WebServices.RegisterLinksApiUrl = new Uri(Walter.Web.FireWall.DefaultEndpoints.DefaultLinks.SiteMapEndPoint, UriKind.Relative);
                options.WebServices.BeaconApiUrl = new Uri(Walter.Web.FireWall.DefaultEndpoints.DefaultLinks.BeaconPoint, UriKind.Relative);
                options.WebServices.CSPReportUrl = new Uri(Walter.Web.FireWall.DefaultEndpoints.DefaultLinks.CSPViolation, UriKind.Relative);

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
                .UseDatabase(connectionString: configuration.GetConnectionString("fireWallStateNope"), schema: "dbo", dataRetention: TimeSpan.FromDays(90))
                ;
            //create default file provider
            CommonHelper.DefaultFileProvider = new NopFileProvider(webHostEnvironment);

            //initialize plugins
            var mvcCoreBuilder = services.AddMvcCore();
            mvcCoreBuilder.PartManager.InitializePlugins(nopConfig);
            
            //add reporting endpoints for the firewall
            mvcCoreBuilder.AddApplicationPart(Assembly.GetAssembly(typeof(Walter.Web.FireWall.DefaultEndpoints.ReportingController)));
            mvcCoreBuilder.AddMvcOptions(options => options.Filters.Add<Walter.Web.FireWall.Filters.FireWallFilter>());


            //create engine and configure service provider
            var engine = EngineContext.Create();

            engine.ConfigureServices(services, configuration, nopConfig);

            return (engine, nopConfig);
        }

        /// <summary>
        /// Create, bind and register as service the specified configuration parameters 
        /// </summary>
        /// <typeparam name="TConfig">Configuration parameters</typeparam>
        /// <param name="services">Collection of service descriptors</param>
        /// <param name="configuration">Set of key/value application configuration properties</param>
        /// <returns>Instance of configuration parameters</returns>
        public static TConfig ConfigureStartupConfig<TConfig>(this IServiceCollection services, IConfiguration configuration) where TConfig : class, new()
        {
            if (services == null)
                throw new ArgumentNullException(nameof(services));

            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));

            //create instance of config
            var config = new TConfig();

            //bind it to the appropriate section of configuration
            configuration.Bind(config);

            //and register it as a service
            services.AddSingleton(config);

            return config;
        }

        /// <summary>
        /// Register HttpContextAccessor
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        public static void AddHttpContextAccessor(this IServiceCollection services)
        {
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        }

        /// <summary>
        /// Adds services required for anti-forgery support
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        public static void AddAntiForgery(this IServiceCollection services)
        {
            //override cookie name
            services.AddAntiforgery(options =>
            {
                options.Cookie.Name = $"{NopCookieDefaults.Prefix}{NopCookieDefaults.AntiforgeryCookie}";

                //whether to allow the use of anti-forgery cookies from SSL protected page on the other store pages which are not
                options.Cookie.SecurePolicy = DataSettingsManager.DatabaseIsInstalled && EngineContext.Current.Resolve<IStoreContext>().CurrentStore.SslEnabled
                    ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.None;
            });
        }

        /// <summary>
        /// Adds services required for application session state
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        public static void AddHttpSession(this IServiceCollection services)
        {
            services.AddSession(options =>
            {
                options.Cookie.Name = $"{NopCookieDefaults.Prefix}{NopCookieDefaults.SessionCookie}";
                options.Cookie.HttpOnly = true;

                //whether to allow the use of session values from SSL protected page on the other store pages which are not
                options.Cookie.SecurePolicy = DataSettingsManager.DatabaseIsInstalled && EngineContext.Current.Resolve<IStoreContext>().CurrentStore.SslEnabled
                    ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.None;
            });
        }

        /// <summary>
        /// Adds services required for themes support
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        public static void AddThemes(this IServiceCollection services)
        {
            if (!DataSettingsManager.DatabaseIsInstalled)
                return;

            //themes support
            services.Configure<RazorViewEngineOptions>(options =>
            {
                options.ViewLocationExpanders.Add(new ThemeableViewLocationExpander());
            });
        }

        /// <summary>
        /// Adds data protection services
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        public static void AddNopDataProtection(this IServiceCollection services)
        {
            //check whether to persist data protection in Redis
            var nopConfig = services.BuildServiceProvider().GetRequiredService<NopConfig>();
            if (nopConfig.RedisEnabled && nopConfig.UseRedisToStoreDataProtectionKeys)
            {
                //store keys in Redis
                services.AddDataProtection().PersistKeysToStackExchangeRedis(() =>
                {
                    var redisConnectionWrapper = EngineContext.Current.Resolve<IRedisConnectionWrapper>();
                    return redisConnectionWrapper.GetDatabase(nopConfig.RedisDatabaseId ?? (int)RedisDatabaseNumber.DataProtectionKeys);
                }, NopDataProtectionDefaults.RedisDataProtectionKey);
            }
            else if (nopConfig.AzureBlobStorageEnabled && nopConfig.UseAzureBlobStorageToStoreDataProtectionKeys)
            {
                var cloudStorageAccount = CloudStorageAccount.Parse(nopConfig.AzureBlobStorageConnectionString);

                var client = cloudStorageAccount.CreateCloudBlobClient();
                var container = client.GetContainerReference(nopConfig.AzureBlobStorageContainerNameForDataProtectionKeys);

                var dataProtectionBuilder = services.AddDataProtection().PersistKeysToAzureBlobStorage(container, NopDataProtectionDefaults.AzureDataProtectionKeyFile);

                if (!nopConfig.EncryptDataProtectionKeysWithAzureKeyVault)
                    return;

                var tokenProvider = new AzureServiceTokenProvider();
                var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback));

                dataProtectionBuilder.ProtectKeysWithAzureKeyVault(keyVaultClient, nopConfig.AzureKeyVaultIdForDataProtectionKeys);
            }
            else
            {
                var dataProtectionKeysPath = CommonHelper.DefaultFileProvider.MapPath(NopDataProtectionDefaults.DataProtectionKeysPath);
                var dataProtectionKeysFolder = new System.IO.DirectoryInfo(dataProtectionKeysPath);

                //configure the data protection system to persist keys to the specified directory
                services.AddDataProtection().PersistKeysToFileSystem(dataProtectionKeysFolder);
            }
        }

        /// <summary>
        /// Adds authentication service
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        public static void AddNopAuthentication(this IServiceCollection services)
        {
            //set default authentication schemes
            var authenticationBuilder = services.AddAuthentication(options =>
            {
                options.DefaultChallengeScheme = NopAuthenticationDefaults.AuthenticationScheme;
                options.DefaultScheme = NopAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = NopAuthenticationDefaults.ExternalAuthenticationScheme;
            });

            //add main cookie authentication
            authenticationBuilder.AddCookie(NopAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.Cookie.Name = $"{NopCookieDefaults.Prefix}{NopCookieDefaults.AuthenticationCookie}";
                options.Cookie.HttpOnly = true;
                options.LoginPath = NopAuthenticationDefaults.LoginPath;
                options.AccessDeniedPath = NopAuthenticationDefaults.AccessDeniedPath;

                //whether to allow the use of authentication cookies from SSL protected page on the other store pages which are not
                options.Cookie.SecurePolicy = DataSettingsManager.DatabaseIsInstalled && EngineContext.Current.Resolve<IStoreContext>().CurrentStore.SslEnabled
                    ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.None;
            });

            //add external authentication
            authenticationBuilder.AddCookie(NopAuthenticationDefaults.ExternalAuthenticationScheme, options =>
            {
                options.Cookie.Name = $"{NopCookieDefaults.Prefix}{NopCookieDefaults.ExternalAuthenticationCookie}";
                options.Cookie.HttpOnly = true;
                options.LoginPath = NopAuthenticationDefaults.LoginPath;
                options.AccessDeniedPath = NopAuthenticationDefaults.AccessDeniedPath;

                //whether to allow the use of authentication cookies from SSL protected page on the other store pages which are not
                options.Cookie.SecurePolicy = DataSettingsManager.DatabaseIsInstalled && EngineContext.Current.Resolve<IStoreContext>().CurrentStore.SslEnabled
                    ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.None;
            });

            //register and configure external authentication plugins now
            var typeFinder = new WebAppTypeFinder();
            var externalAuthConfigurations = typeFinder.FindClassesOfType<IExternalAuthenticationRegistrar>();
            var externalAuthInstances = externalAuthConfigurations
                .Select(x => (IExternalAuthenticationRegistrar)Activator.CreateInstance(x));

            foreach (var instance in externalAuthInstances)
                instance.Configure(authenticationBuilder);
        }

        /// <summary>
        /// Add and configure MVC for the application
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        /// <returns>A builder for configuring MVC services</returns>
        public static IMvcBuilder AddNopMvc(this IServiceCollection services)
        {
            //add basic MVC feature
            var mvcBuilder = services.AddControllersWithViews();

            mvcBuilder.AddRazorRuntimeCompilation();

            var nopConfig = services.BuildServiceProvider().GetRequiredService<NopConfig>();
            if (nopConfig.UseSessionStateTempDataProvider)
            {
                //use session-based temp data provider
                mvcBuilder.AddSessionStateTempDataProvider();
            }
            else
            {
                //use cookie-based temp data provider
                mvcBuilder.AddCookieTempDataProvider(options =>
                {
                    options.Cookie.Name = $"{NopCookieDefaults.Prefix}{NopCookieDefaults.TempDataCookie}";

                    //whether to allow the use of cookies from SSL protected page on the other store pages which are not
                    options.Cookie.SecurePolicy = DataSettingsManager.DatabaseIsInstalled && EngineContext.Current.Resolve<IStoreContext>().CurrentStore.SslEnabled
                        ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.None;
                });
            }

            services.AddRazorPages();

            //MVC now serializes JSON with camel case names by default, use this code to avoid it
            mvcBuilder.AddNewtonsoftJson(options => options.SerializerSettings.ContractResolver = new DefaultContractResolver());

            //add custom display metadata provider
            mvcBuilder.AddMvcOptions(options => options.ModelMetadataDetailsProviders.Add(new NopMetadataProvider()));

            //add custom model binder provider (to the top of the provider list)
            mvcBuilder.AddMvcOptions(options => options.ModelBinderProviders.Insert(0, new NopModelBinderProvider()));

            //add fluent validation
            mvcBuilder.AddFluentValidation(configuration =>
            {
                //register all available validators from Nop assemblies
                var assemblies = mvcBuilder.PartManager.ApplicationParts
                    .OfType<AssemblyPart>()
                    .Where(part => part.Name.StartsWith("Nop", StringComparison.InvariantCultureIgnoreCase))
                    .Select(part => part.Assembly);
                configuration.RegisterValidatorsFromAssemblies(assemblies);

                //implicit/automatic validation of child properties
                configuration.ImplicitlyValidateChildProperties = true;
            });

            //register controllers as services, it'll allow to override them
            mvcBuilder.AddControllersAsServices();

            return mvcBuilder;
        }

        /// <summary>
        /// Register custom RedirectResultExecutor
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        public static void AddNopRedirectResultExecutor(this IServiceCollection services)
        {
            //we use custom redirect executor as a workaround to allow using non-ASCII characters in redirect URLs
            services.AddSingleton<IActionResultExecutor<RedirectResult>, NopRedirectResultExecutor>();
        }

        /// <summary>
        /// Add and configure MiniProfiler service
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        public static void AddNopMiniProfiler(this IServiceCollection services)
        {
            //whether database is already installed
            if (!DataSettingsManager.DatabaseIsInstalled)
                return;

            services.AddMiniProfiler(miniProfilerOptions =>
            {
                //use memory cache provider for storing each result
                ((MemoryCacheStorage)miniProfilerOptions.Storage).CacheDuration = TimeSpan.FromMinutes(60);

                //whether MiniProfiler should be displayed
                miniProfilerOptions.ShouldProfile = request =>
                    EngineContext.Current.Resolve<StoreInformationSettings>().DisplayMiniProfilerInPublicStore;

                //determine who can access the MiniProfiler results
                miniProfilerOptions.ResultsAuthorize = request =>
                    !EngineContext.Current.Resolve<StoreInformationSettings>().DisplayMiniProfilerForAdminOnly ||
                    EngineContext.Current.Resolve<IPermissionService>().Authorize(StandardPermissionProvider.AccessAdminPanel);
            });
        }

        /// <summary>
        /// Add and configure WebMarkupMin service
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        public static void AddNopWebMarkupMin(this IServiceCollection services)
        {
            //check whether database is installed
            if (!DataSettingsManager.DatabaseIsInstalled)
                return;

            services
                .AddWebMarkupMin(options =>
                {
                    options.AllowMinificationInDevelopmentEnvironment = true;
                    options.AllowCompressionInDevelopmentEnvironment = true;
                    options.DisableMinification = !EngineContext.Current.Resolve<CommonSettings>().EnableHtmlMinification;
                    options.DisableCompression = true;
                    options.DisablePoweredByHttpHeaders = true;
                })
                .AddHtmlMinification(options =>
                {
                    options.CssMinifierFactory = new NUglifyCssMinifierFactory();
                    options.JsMinifierFactory = new NUglifyJsMinifierFactory();
                })
                .AddXmlMinification(options =>
                {
                    var settings = options.MinificationSettings;
                    settings.RenderEmptyTagsWithSpace = true;
                    settings.CollapseTagsWithoutContent = true;
                });
        }

        /// <summary>
        /// Add and configure default HTTP clients
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        public static void AddNopHttpClients(this IServiceCollection services)
        {
            //default client
            services.AddHttpClient(NopHttpDefaults.DefaultHttpClient).WithProxy();

            //client to request current store
            services.AddHttpClient<StoreHttpClient>();

            //client to request nopCommerce official site
            services.AddHttpClient<NopHttpClient>().WithProxy();

            //client to request reCAPTCHA service
            services.AddHttpClient<CaptchaHttpClient>().WithProxy();
        }
    }
}