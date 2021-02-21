# ![](https://cdn.asp-waf.com/img/FireWall.png) ASP-WAF Sample Application Firewall
The bellow sample shows a minimal MVC application that could execute in .net Core 3.1 or .Net 5.x
The sample is intentionally kept minimalistic so that it's easy to follow and replicate.

## The setup
The absolute first thing needed is the [firewall NuGet package](https://www.nuget.org/packages/Walter.Web.FireWall/). You can install it any way you like, ideal however is to get if from NuGet the way you get all your packages.


### Step 1 Inject the firewall 
After having downloaded and installed that latest firewall version you are ready to integrate the firewall with 
the dependency injection of .net this sample demonstrates this in the [Startup.cs](https://github.com/ASP-WAF/FireWall/blob/master/Samples/MVC_Core_31_Application/MVC_Core_31_Application/Startup.cs) file of this project as shown in the bellow sample.

```c#
/*Inject the firewall with a given configuration in your application
* You can use your own class and derive the firewall from that as a base class
*  then you can tune the configuration options to reflect your preferences
*  see the online documentation for more information on the configuration options
*  at https://firewallapi.asp-waf.com/?topic=html/AllMembers.T-Walter.Web.FireWall.IFireWallConfig.htm
*  
*  The sample configuration can also be stored and loaded in json configuration, perhaps make the configuration
*  in code first and then save it as json to get started as the number of configuration options are abundant
*/
services.AddFireWall<MyFireWall>(FireWallTrial.License, FireWallTrial.DomainKey, new Uri("https://www.mydomain.com", UriKind.Absolute), options =>
{
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
    .UseDatabase(connectionString: Configuration.GetConnectionString("FireWallState"), schema: "dbo", dataRetention: TimeSpan.FromDays(90));
````

The above sample is not the *minimal configuration* and you will likely specify quite a few more attributes but 
it highlights some of the more popular settings and helps you get started. We recommend to use your IntelliSense 
and have a look at what’s available or view the [online documentation](https://firewallapi.asp-waf.com/?topic=html/AllMembers.T-Walter.Web.FireWall.IFireWallConfig.htm).
<br>

### 2nd setup step - Activate the firewall on each request
Still in the ConfigureServices method of the setup.cs class you will need to update the way the 
MVC pipeline executes by registering the firewall filter. The bellow sample registers the firewall
as well as the privacy filter that will inform your browser of the header configuration privacy settings.

````c#
//configure the firewall to be active on each request by registering the firewall filter
services.AddMvc(setupAction =>
{
    //enable the firewall on all endpoints in this application 
    setupAction.Filters.Add<Walter.Web.FireWall.Filters.FireWallFilter>();
    //inform the browser of our privacy policy if you render views
    setupAction.Filters.Add<Walter.Web.FireWall.Filters.PrivacyPreferencesFilter>();
});
````
<br>

### 3rd Setup step (if using views can be skipped if you only use API endpoints)
Have a look at _layout.cshtml and you may notice that we have integrated user detection using the same string 
constant as used in the controllers\UserDiscoveryController.cs and Startup.cs file by using this code snippet.

The sample assumes that you create your own user discovery controller and not use the [Walter.Web.FireWall.DefaultEndpoints NuGet Package](https://www.nuget.org/packages/Walter.Web.FireWall.DefaultEndpoints/)
```html
    @*Inject firewall user discovery script in the view template*@
    <script src="@Url.Content(MVC_Core_31_Application.Links.UserEndpointJavaScript)"></script>
    @*
```  

As you do not use the [Walter.Web.FireWall.DefaultEndpoints](https://www.nuget.org/packages/Walter.Web.FireWall.DefaultEndpoints/) NuGet Package this sample shows how to feed the User discovery data back to the firewall in the [Controllers\UserDiscoveryController.cs file](https://github.com/ASP-WAF/FireWall/blob/master/Samples/MVC_Core_31_Application/MVC_Core_31_Application/Controllers/UserDiscoveryController.cs).



## Test the implementation
You can query the firewall state as well as monitor the health by using the build-in API as shown in the bellow sample. 
The URL to the project would be ~/API/Reporting/Text and is defined in the previousely mentioned [Controllers\UserDiscoveryController.cs](https://github.com/ASP-WAF/FireWall/blob/master/Samples/MVC_Core_31_Application/MVC_Core_31_Application/Controllers/UserDiscoveryController.cs) file



````c#
/// <summary>
/// an API endpoint that can be called from an API endpoint and is protected using the firewall rule-set for 
/// API Endpoints
/// </summary>
/// <remarks>
/// there is also a Json version allowing you to automate monitoring
/// </remarks>
/// <returns>the text report of the firewall, </returns>
[Ignore(skip: FireWallGuardModules.API_ENDPOINT_LAX)]
[NoCache]
[HttpGet("API/Reporting/Text")]
public string Get()
{
    Response.Headers["X-Remote-Address"] = _page.IPAddress.ToString();
    Response.Headers["Connection"] = "Close";
    Response.Headers["Cache-Control"] = "no-cache";
    Response.ContentType = "text/plain";
    var list = new StringBuilder();
    list.AppendLine($"Firewall version: {_fireWall.FirewallModuleVersion} status {_fireWall.State} license {_fireWall.License.LicenseKey.Domain.DomainUrl}: {_fireWall.License.LicenseKey.LicenseLevel}");
    list.AppendLine("---------------------------------------------------");

    //if called from inside the LAN
    if (_page.IPAddress.IsInLocalSubnet())
    {
        list.AppendLine(_fireWall.Report(ReportTypes.ALL));
    }
    else
    {
        list.AppendLine(_fireWall.Report(ReportTypes.Activity | ReportTypes.KPI));
    }


    if (!(_page.Exception is null))
    {
        list.AppendLine("---------------------REQUEST-----------------------");
        list.Append(_page.ToString());

    }
    list.AppendLine("---------------------------------------------------");
    return list.ToString();
}
````


