# ![](https://cdn.asp-waf.com/img/FireWall.png) ASP-WAF Application Firewall

You have made a smart choice and have made a step to securing your web application from serious harm by using this firewall. 

There are 4 license levels available that have different functionality and allow the use of NuGet extension packages. 

The license levels are:
- **COMMUNITY** This is free and helps to protect as well as report on the penetration and malicious intentions of your visitors.
- **BASE** A light-weight fully functional firewall that will do all the things you like a WAF to do and then some!
- **SMALL BUSINESS** A firewall targeting small businesses that offer online shopping as well as the need to comply with GDPR privacy. This version allows you to use all extensions  and performs real-time reporting.
- **ENTERPRICE** A firewall that will integrate with the windows firewall extend protection to the whole server when malicious activity is detected as they will attack the whole server, not just the web application.

## SUPPORT

Installation support is FREE for all license levels including trial usage.
We offer:

1. Mail via support@asp-waf.com
2. Phone via +352 661 464 601, +352 661 464 633
3. WhatsApp via +352 661 464 601
4. Live Share (send link request via mail or WhatsApp)

#### Why reach out to us for support?
Installation of Firewall packages need sometimes extra attention:  Firewall installation can block itself, there can be some desktop server communication issues, different hardware in same network reacts sometimes different than expected.


## How to get started

Have a look at the various ways you can configure the firewall by :
 1. download the getting started manual and understand how it work and see code samples
    https://www.asp-waf.com/download/ASP-WAF-FireWall-Getting-Started.pdf
 2. look at the full ASP-WAF framework API online by opening this link:
    https://firewallapi.asp-waf.com/ or download the API using compiled
    off-line help file found at https://www.asp-waf.com/download/ASP-WAF-FireWall.chm
 3. The sample implementation in this samples in this GitHub repository like
   [Simple MVC App](https://github.com/ASP-WAF/FireWall/blob/master/Samples/MVC_Core_31_Application/MVC_Core_31_Application/Startup.cs) with a simple implementation
   [Nope Shopping card demo](https://github.com/ASP-WAF/FireWall/tree/master/Samples/NopeCommerce) with an integration into a existing application as well as extending the firewall with this [GEO Sample](https://github.com/ASP-WAF/FireWall/tree/master/Samples/IGeoFactory%20implementation)

Getting started is easy, have a look at the samples online at www.asp-waf.com but basically all you need to do is the two services configurations:
````C#    
public void ConfigureServices(IServiceCollection services)
{
    //recommended feature (distributed memory cashing needs license)
    services.AddMemoryCache();

    services.AddFireWall( FireWallTrial.License
                    , FireWallTrial.DomainKey 
                    , domainName: new Uri("https://www.your-domain.dll", UriKind.Absolute), options =>
                    {
                       //set your options you need, there are several options like rules and reporting there are however 2 key properties 
                       
                        //1. tell the firewall that your not using session storage (important when load balancing the site)
					    options.UseSession = false;
                        
                        //2. tell the firewall the rule engine to load
                        options.FireWallMode= FireWallProtectionModes.WebSiteWithApi;

                    })//you do not need a firewall database for state storage but it does perform paster and you can retain data longer
                    .UseDatabase(connectionString: Configuration.GetConnectionString("FireWallState"),schema:"dbo",dataRetention: TimeSpan.FromDays(365));
    
    // minimal protection
    services.AddMvc(options =>
    {
        options.Filters.Add<Walter.Web.FireWall.Filters.FireWallFilter>();
    });

}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    ...
    //advanced protection
    app.UseFireWall();
    ...
}
````
For larger installations we recommend using database storage for the firewall state.
````C#
services.AddFireWall( FireWallTrial.License
                    , FireWallTrial.DomainKey 
                    , domainName: new Uri("https://www.your-domain.dll", UriKind.Absolute), options =>
                    {
                    //set your options
                    }).UserDatabase(connectionString:Configuration.GetConnectionString("FireWall") ,schema:"dbo", dataRetention: TimeSpan.FromDays(365));
services.AddMvc(options =>
{                
    options.Filters.Add<Walter.Web.FireWall.Filters.FireWallFilter>();
    options.Filters.Add<Walter.Web.FireWall.Filters.PrivacyPreferencesFilter>();
}).AddApplicationPart(Assembly.GetAssembly(typeof(Walter.Web.FireWall.DefaultEndpoints.ReportingController)));
````
### Configuration

You configure the firewall rule engine right in the options settings during the service configuration. What is great however is that you can fine-tune the rules on each controller as well as each action or page endpoint using annotations. 

You can use the annotations from Walter.Web.FireWall.Annotations to protect your endpoints. The following samples shows that only post backs that are excepted are those that actually came from 
the page instance you loaded, or the user must be in the same session and when you rendered the 
page & JavaScript:
````c#
[HttpPost]
[ModelFilter(Associations = RequestersAssociations.InCurrentPage | RequestersAssociations.InCurrentSession)]
[Ignore(skip:FireWallGuardModules.API_ENDPOINT)]
public IActionResult AjaxUpdate(OrderModel model)
{
    if (ModelState.IsValid)
    {
        //your code
        return Ok();
    }
    return this.BadRequest("Model not valid");
}
````

## Extending the firewall

We did not ship you a black-box, you can extend and control the firewall using your on instance
when you inherit from the Walter.Web.FireWall.FireWallBase class

You register your own base class by using the services.AddFireWall<T>() extension method
````c#
services.AddFireWall<MyFireWall>(FireWallTrial.License
                    , FireWallTrial.DomainKey 
                    , domainName: new Uri("https://www.your-domain.dll", UriKind.Absolute), options =>
                    {
                    //set your options
                    });
````
After this you can control the firewall via events and inject your own reporting interfaces
making the firewall do what you need and not what we, as the vendor, anticipated.


#### GDPR
You can make sure that you never leak any private data when using the Walter.Web.FireWall.CookieStore
The cookie store will store the data on your server and only set's the "empty" cookie in the clients 
browser. 
````C#
services.AddFireWall( FireWallTrial.License
                    , FireWallTrial.DomainKey 
                    , domainName: new Uri("https://www.your-domain.dll", UriKind.Absolute), options =>
                    {
                    //set your options
                    }).UseDBCookieStore(Configuration.GetConnectionString("FireWallCookieDatabase"));

services.AddMvc(options =>
{
    options.Filters.Add<Walter.Web.FireWall.Filters.FireWallFilter>();
});
````

To use the feature simply talk to the cookie via your user as shown here

````C#
public class HomeController : Controller
{
    
    private readonly IPageRequest _page;
    private readonly ILatLongRepository _latLongRepository;

    public HomeController(IPageRequest page, ILatLongRepository latLongRepository)
    {
        _page = page;
        _latLongRepository = latLongRepository;
    }

    public async Task<IActionResult> Index()
    {
       if(!_page.User.TryReadCookie("Telephone", out var phone))
       {
           phone = "001.123.567.89 ext 123";
       }
       await _page.User.WriteCookieAsync("Telephone", phone,TimeSpan.FromSeconds(60)).ConfigureAwait(false);
    }

}
````    
    More on the cookie store online here :
    https://firewallapi.asp-waf.com/?topic=html/T-Microsoft.Extensions.DependencyInjection.CookieStoreBuilderExtensions.htm


### USER-AGENT 
You can receive quite some information from a page looking at the reputation of the user's device via the 
IPageRequest.User.UserAgent property.
````C#
public async Task<IActionResult> Index()
{
    //device reputation
    var okRequests = _page.User.UserAgent.MetaData.Counters.Benevolent;
    var suspectRequests = _page.User.UserAgent.MetaData.Counters.Malicious;

    //user reputation
     var fireWallUser=  _page.User.AsFirewallUser();
     int visits = fireWallUser.Visits;
     int blocked= fireWallUser.ViolationsBlockCount;
     bool spoofing= fireWallUser.IsSpoofing;


     //user engagement with the site
     int mc = fireWallUser.MouseCount;
     int kc = fireWallUser.KeyboardCount;
     int tc = fireWallUser.TouchCount;

    // user-agent parsing     
    var assumePhone = _page.User.UserAgent.MetaData.DeviceType == UADeviceType.SmartPhone; 
    var assumeTabled= _page.User.UserAgent.MetaData.DeviceType == UADeviceType.Tablet ;
}
````
The firewall, if not configured, will store data to disk. You can use a database by updating the configuration or
setting the database explicitly
````C#
    services.AddFireWall( FireWallTrial.License
                        , FireWallTrial.DomainKey 
                        , domainName: new Uri("https://www.your-domain.dll", UriKind.Absolute), options =>
                        {
                           //set your options

                           //always store user agent reputation in a database
                           options.UserAgent.ConnectionString = Configuration.GetConnectionString("UserAgent");
                           options.UserAgent.SchemaName = Configuration.GetConnectionString("dbo");

                        });

    services.AddMvc(options =>
    {
        options.Filters.Add<Walter.Web.FireWall.Filters.FireWallFilter>();
    });
````
More information and samples can be found at the online [UserAgentDBStore]( 
https://firewallapi.asp-waf.com/?topic=html/M-Microsoft.Extensions.DependencyInjection.FireWallBuilderExtensions.UseUserAgentDBStore--1_1.htm) documentation

	
## Remote Desktop
You can observe the firewall's recomedation in real-time by using the open source project [asp-waf desktop](https://www.asp-waf.com/abuse). The desk top will allo you to monitor, perform quick actions as well as generate abuse reports that can be send to internet service providers. The best ios that you can alter the desktop to fit your needs as it is open source. You can get the .NET 5.0 PRISM WPF by [downloading the source here](https://github.com/PeterPann23/FireWallDesktop) 	
	
### LICENSE
You can try the firewall using the trial keys or register your own version today go and get your own license at https://www.asp-waf.com and register your copy today.

### DATA EXCHANGE
Users with a license level of Trial, Community or Base may exchange known malicious user activity
with the subscription server. If you do not wish to participate with the data improvement program
you will need to get a Small business or enterprise license

	
