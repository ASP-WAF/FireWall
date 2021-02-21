# About this nope sample
The Nope shopping card sample shows how to integrate the firewall in a real application used by thousands of companies by inspecting the code.

If you are new to the ASP-WAF FireWall then please look at the [MVC Core 3.1 Application](https://github.com/ASP-WAF/FireWall/blob/master/Samples/MVC_Core_31_Application/MVC_Core_31_Application/Readme.md) first.

## Before running the application
The power of the Nope framework is its plug-in system. This can however also cause frustration as when downloading and running it the first time you will notice that the solution builds but fails to run as it misses key depended on plugins. You can solve this by Right-clicking the Plugins folder and select *build* from the pop-up menu.

This code demonstrates the use of the Walter.Web.FireWall framework but is not intended for production as is. Please note that this demo uses a [DBHelper](https://github.com/ASP-WAF/FireWall/blob/master/Samples/NopeCommerce/Presentation/Nop.Web.Framework/DBHelper.cs) that will create a database on a localdb instance, while this work well in development it will likely fail in a hosted environment. 

````C#
public Startup(IConfiguration configuration, IWebHostEnvironment webHostEnvironment)
{
    _configuration = configuration;
    _webHostEnvironment = webHostEnvironment;
    // create 
    DBHelper.CreateDatabases(false, _configuration, "fireWallStateNope");
}
````

## The Setup 
The firewall integration can be done in either the Nope.Web.Framework project or in the Nope.Web project. We have chosen a hybrid option as if is most natural for most developers to start in the Nop.Web application. 
### Registering the firewall with the dependency system
You can inject the configuration using the default appsettings.json, however, configuring the settings in code allows you to play with the setting via IntelliSense. 

````c#
/*Inject the firewall with a given configuration in your application
 * You can use your own class and derive the firewall from that as a base class
 *  then you can tune the configuration options to reflect your preferences
 *  see the online documentation for more information on the configuration options
 *  at https://firewallapi.asp-waf.com/?topic=html/AllMembers.T-Walter.Web.FireWall.IFireWallConfig.htm
 *  
 *  The sample configuration can also be stored and loaded in json configuration, perhaps make the configuration
 *  in code first and then save it as json to get started as the number of configuration options are abundant
 */
services.AddFireWall<MyFireWall>(license: FireWallTrial.License,domainLicense: FireWallTrial.DomainKey
    ,domainName: new Uri("https://www.mydomain.com", UriKind.Absolute), options => {

    //set your public IP address when debugging so you can simulate IP based protection     
    //your real public IP address is accessible at  Walter.Net.Networking.RuntimeValues.PublicIpAddress 
    options.PublicIpAddress = IPAddress.Parse("8.8.8.4");

    //use this password as a base when encrypting data so no one else can read it, just do not change it....
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

    //protect all endpoints that are derived from the Nope base controllers
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
                         .AddXssProtectionBlockAndReport(Links.CSP)
                         .AddContentSecurityPolicyTrustOnlySelf();

    options.OnEndpointsCreated += Options_OnEndpointsCreated;


})//store firewall state in a database making the firewall faster and allow it for the firewall to maintain large data volumes
.UseDatabase(connectionString: _configuration.GetConnectionString("fireWallStateNope"), schema: "dbo", dataRetention: TimeSpan.FromDays(90));

````

### Always use memory cache
The registration of the firewall is done in [Startup.cs starting at line 84](https://github.com/ASP-WAF/FireWall/blob/master/Samples/NopeCommerce/Presentation/Nop.Web/Startup.cs). As you can see we have added code comments explaining the reasoning behind the reasoning. There are several good 3rd party cashing systems and the firewall can do without but why would you? You can use the native injected MemoryCashe you write and inject your own, the FireWall framework is happy to use any IMemoryCache interface.

````c#
 /* Use memory cashing to speed up the application
 *  you can use plugins like Redis or SQL backed cashing if you are using fail-over servers
 *  when using cashing the discovered ISP data of those that are attacking you will be re-used
 *  and do not have to be re-discovered on each request.
 */
services.AddMemoryCache();
````

### The use of a custom firewall
This sample overwrites the default firewall implementation and uses an implementation native to the implementation. The use of a custom implementation allows you to take control of the firewall and test your rules while developing the application as you can use events and add breakpoints when the firewall triggers such events allowing you to override the firewall’s behaviour and catch miss-configurations and potential false positives as you may have designed your application in a way that facilitates a known vulnerability. 

You can view the custom FireWall used in this application by navigating to the 
[MyFireWall.cs](https://github.com/ASP-WAF/FireWall/blob/master/Samples/NopeCommerce/Presentation/Nop.Web.Framework/MyFireWall.cs) file in the Nop.Web.Framework project.


### Avoid MagicStrings and use custom Links in your implementation
This installation makes use of a custom implementation of the user discovery implementation. It does this by defining and using the same routs all starting with this links class located in [Startup.cs:24](https://github.com/ASP-WAF/FireWall/blob/master/Samples/NopeCommerce/Presentation/Nop.Web/Startup.cs).
````C#
/// <summary>
/// if any other plugin uses the same routs as the firewall then you just change these
/// values and the configuration will adapt ensuring the firewall will work
/// as expected
/// </summary>
public static class Links
{
    public const string SiteMapEndPoint = "api/SiteMapPageRequest";
    public const string IsUserEndpoint = "api/UserDiscovery";
    public const string BeaconPoint = "api/BeaconPageRequest";
    public const string CSP = "api/CSP";
    public const string UserEndpointJavaScript = "js/jquery.legasy.js";
}
````    
The discovery is triggered by injecting a JavaScript file that is generated on each request. In the Nope framework you inject javascript in the site layout template by altering the  [Views/shared/\_Root.Head.cshtml:34](https://github.com/ASP-WAF/FireWall/blob/master/Samples/NopeCommerce/Presentation/Nop.Web/Views/Shared/_Root.Head.cshtml) 
````HTML
Html.AppendScriptParts(ResourceLocation.Footer, Url.Content(Nop.Web.Links.UserEndpointJavaScript));
````
This will call the other endpoints defined in firewall configuration that are then instructing the javascript to call the endpoints specified in [Controllers/FireWallController.cs](https://github.com/ASP-WAF/FireWall/blob/master/Samples/NopeCommerce/Presentation/Nop.Web/Controllers/FireWallController.cs)

You can view the code in the controller but basically, you should pay attention to the annotation on the action. You have a [NoCash](https://firewallapi.asp-waf.com/?topic=html/T-Walter.Web.FireWall.Annotations.NoCacheAttribute.htm) making sure the browser does not cash the script file as well as the [Ignore](https://firewallapi.asp-waf.com/?topic=html/AllMembers.T-Walter.Web.FireWall.Annotations.IgnoreAttribute.htm) attribute instructing the firewall to protect the endpoint using the EmbeddedResources modules
````C#
/// <summary>
/// Generate The JavaScript for user detection based on the user
/// </summary>
/// <remarks>
/// Script is called by injecting via     
/// Html.AppendScriptParts(ResourceLocation.Footer, Url.Content(Nop.Web.Links.UserEndpointJavaScript));
/// </remarks>
/// <returns>a JavaScript for this user and this page</returns>
[HttpGet]
[NoCache]
[Route(Links.UserEndpointJavaScript)]
[Ignore(Walter.Web.FireWall.Filters.FireWallGuardModules.EmbeddedResources)]
public FileContentResult ValidateUser()
{
    //use the ID to force reloading the script after the user has logged in or logged off
    //as the firewall will create a different script for logged in users.
    try
    {
        if (_fireWall.TryGetValidateUserJavaScript(page: _page, out var javaScript))
        {
            var file = File(fileContents: javaScript, contentType: "text/javascript");
            file.LastModified = DateTime.UtcNow;
            file.FileDownloadName = _page.OriginalUrl.AbsoluteUri;
            return file;
        }
        else
        {
            _logger?.LogError("ValidateUser javascript generation failed for {Page}", _page.SessionPageGroupNumber);
            javaScript = UTF8Encoding.UTF8.GetBytes($"console.log('could not generate userValidation')");
            return File(fileContents: javaScript, contentType: "text/javascript");
        }
    }
    catch (ArgumentException e)
    {
        _fireWall.LogException<RunTimeErrors>(RunTimeErrors.ArgumentNullException, e, "Missing a configuration element or using wrong release for your deployment");
        var javaScript = System.Diagnostics.Debugger.IsAttached
            ? UTF8Encoding.UTF8.GetBytes($"console.log('could not generate userValidation due to {e.Message}')")
            : UTF8Encoding.UTF8.GetBytes($"//Validate log {DateTime.Now} for errors and update settings");
        return File(fileContents: javaScript, contentType: "text/javascript");
    }
    catch (Exception e)
    {
        _fireWall.LogException<RunTimeErrors>(RunTimeErrors.ArgumentNullException, e, $"User type discovery will not work as good as it could please fix {e.Message}");
        var javaScript = UTF8Encoding.UTF8.GetBytes($"console.log('could not generate userValidation due to {e.Message}')");
        return File(fileContents: javaScript, contentType: "text/javascript");
    }
    finally
    {
        _logger?.LogInformation("ValidateUser called");
    }
}
````
## Health Monitoring 
You can access the firewall's state by querying the internal storage and use this in your automated monitoring. There are several risks by making this data available to the public so protect this endpoint by using authentication. We however recommend not relying on authentication only and use the [WhiteListIPAttribute](https://firewallapi.asp-waf.com/?topic=html/AllMembers.T-Walter.Web.FireWall.Annotations.WhiteListIPAttribute.htm) to protect the endpoint.

You can create a [Text or Json report](https://firewallapi.asp-waf.com/?topic=html/M-Walter.Web.FireWall.IFireWall.Report_1.htm) by asking the firewall to generate it based on the details using [ReportTypes](https://firewallapi.asp-waf.com/?topic=html/T-Walter.Web.FireWall.Reporting.ReportTypes.htm) 

The bellow sample is intended to be accessed by humans as defined by the [UsersAttribute](https://firewallapi.asp-waf.com/?topic=html/Overload-Walter.Web.FireWall.Annotations.UsersAttribute.-ctor.htm) using one of several ways it can be configured
````C#
///<summary>A text report showing the state of the firewall</summary>
/// <remaks>
/// only allow humans, this can't be the first page they visit as they have to previously been identified as humans
/// </remaks>
/// <returns>Status result</returns>
[HttpGet]
[Produces("text/plain")]
[Users(UserTypes.IsHuman,redirectToController:"home",redirectAction:"index",maximumAttempts:10, maximumAttemptsInSeconds:60)]
public string Index()
{
   var list = new StringBuilder();
   list.AppendLine($"Firewall version: {_fireWall.FirewallModuleVersion} status {_fireWall.State} license {_fireWall.License.LicenseKey.Domain.DomainUrl}: {_fireWall.License.LicenseKey.LicenseLevel}");
    list.AppendLine("---------------------------------------------------");
    list.AppendLine( _fireWall.Report(ReportTypes.ALL));
    list.AppendLine("---------------------------------------------------");
    return list.ToString();
}
```` 



