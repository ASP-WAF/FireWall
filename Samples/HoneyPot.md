#About the Honey-Pot detector

The honey pot detector allows to detect and interact with applications that are attempting to communicate with your server via a particular port. Understanding who is maliciously trying to exploit the system helps identify bad actors and will allow you to tune the system alerting an attempt by a system classified as being a bad actor and will allow the framework to block any requests and or return a payload. 


## Integrating the honey-pot detector in your application
Integrating the honey-pot listener takes 3 steps.

### step 1:
Foreword ports in your edge-switch to ports monitored by the honey-pot configuration. A recommendation is to map the ports to a free port not used by the server. 
An example map port 22 to port 60022 and configure the honey-port to watch any communication on port 4000

### step 2
Configure the firewall to allow the communication on port 4000.  
  
### step 3
Configure the application to subscribe to the port detections. To do this in the firewall you should use a configuration similar to this:
````C#
services.AddFireWall()
        .UsePortScannerProtection(connectionString: DatabaseConnections.FireWallState, options =>
               {

                   /* map the service ports to a local port on your computer
                   *  Redirect the requests to your computer and open the firewall 
                   *  for the redirected ports */

                   options.SSH = 4000; // map port 22 to port 4000 on your router 
                   options.TSQL = 4001; // map port 1433 to port 4001 on your router 
                   options.Telnet = 4002; // map port 23 to port 4002 on your router 
                   options.MYSQL = 4005; // map port 3306 to port 4005 on your router
                   options.DNS = 4006; // map port 53 to port 4005 on your router
                   options.Telnet 4007; //map port 23 to port 4007 on your router;

                   /*you can manually map port aliases in the range from 0 till 65535*/
                   options.AddOrUpdate(externalPort: 587, internalPort: 4007, name: "ESMTP Extended Simple Mail Transfer Protocol");
                   options.AddOrUpdate(externalPort: 647, internalPort: 4008, name: "DHCP Fail-over");

                   /*Record up-to 8,000 character when someone is trying to attack the service for legal reporting*/
                   options.MaximumDataSizeToAccept = 254;

                   /*Look between every 100ms and 30000ms if someone is trying to gain access to the system */
                   options.PoolFrequency = 100;

                   /* Add a default reply to any connection, you can send a auto reply 
                    * You can use the template values:
                    * {IP}  - the attackers IP address
                    * {Port}- the port being attacked
                    * {Name}- the name of the alias being used
                    * {ISP} - the name of the Internet service provider that the attacker is using will be injected
                    * {Country} - the country name will be injected
                    * to personalize the message or leave it blank to record silently*/
                   options.DefaultReply = "This service is being monitored and we have detected your intentions attack {Name}" +
                                          " via {IP}:{Port} to gain unlawful access to the system, please note that any unlawful" +
                                          " activity will be reported to {ISP} as well as the relevant authorities in {Country}";

               })

````
The above code assumes that you are using the FireWall from NuGet package [Walter.Web.FireWall](https://www.nuget.org/packages/Walter.Web.FireWall/). 
If you are using any of the services that you are monitoring then then map the default ports to custom ports on your router there are 2 steps for this:
1. Map the custom port on the router, an example map 222 to port 22 
2. Use port 222 to connect using SSH 

Please note that a lot attackers are looking for vicems using port scaners to target vunerable IP addresses before attacking a system. You can [have a look](https://www.asp-waf.com/Reporting) at how these attacks are beding executed. 


