__[Home](help.md) | [TagHelpers](taghelpers.md) | Geo | [FireWall Rules](Rules.md)__

# Configuring Geo middleware and tag helpers

### Setup

You have the ability to enable or disable regions, continents and individual countries. You configure geo support by using one of the Walter.Web.FireWall.Geo.* NuGet packages.
Please note that these packages will use 3rd party providers that need individual licensing. Currently we support 


|   #	| Nuget Package name   	| data provider  	| API  	|   Database	|
|---	|---	|---	|---	|---	| ---
|1   	| Walter.Web.FireWall.Geo.Google  	| Google  	|   X	|   -	|
|2   	| Walter.Web.FireWall.Geo.Ip2Location  	|IP2Loaction   	|   X	|  (MS SQL Server script included) 	|
|3   	| Walter.Web.FireWall.Geo.MaxMind  	| MaxMind  	|   X	|   proprietary file format	|

Please note that at any given time you can use only 1 of the above mentioned providers. You install and configure a given provider 
by downloading the proffered NuGet package you need to use your own license.

#### logging
When the log level is set to debug the tag helper will generate detailed output in the web applications specified Logger provider and if debugging it may throw developer specific exceptions. 


### Geographical tag helpers
You can make any of the following HTML tags geographical aware by adding the  *firewall-geo* attribute.
```<a>      ``` ```<body>   ``` ```<button> ``` ```<canvas> ``` ```<col>``` ```<data>   ```
```<div>    ``` ```<footer> ``` ```<h1>     ``` ```<h2>     ``` ```<h3>     ``` ```<h4>     ```
```<header> ``` ```<img> ``` ```<input>  ``` ```<li>     ``` ```<link>   ```
```<meta>   ``` ```<ol> ``` ```<p>```  ```<script> ``` ```<span> ``` ```<submit> ```
```<table>  ``` ```<td> ``` ```<tr> ``` ```<ul>``` ```<video>```

The below sample shows how the attribute can be used to include or exclude elements from the browser.
If the user tries to circumvent the GEO-fencing specified by using VPN provider you can use the VPN provider to suppress this as well, more on using VPN & proxy attribute [here](#vpn-&-proxy-users).
```html
<div firewall-geo="true">
    <p>
      We are sorry this content is not available in your region...
    </p>
</div>

<div firewall-geo class="container">
    <!-- this div will not be included in the output in the location is suppressed-->
    We are happy to show you the below licensed movie
    <video autoplay muted class="bg text-center" id="video" style="width:80%;" >
         <source src="~/Video/CATSTrade.mp4" type="video/mp4">
    </video>
    ...
</did>

<script firewall-geo src="~/js/GeoScript.js"></stript>
```

#### Using  the Geo API in your source code
Being able to fine tune individual elements on a user page will allow for full control in relation to geo-fencing features on your website. The Firewll however can also be use to
take drastic measures when it comes to securing the site from unwanted access.

Say you have a policy that your website is not available from a given country or region as that region is not:
- [X] Being serviced by you
- [X] You are not license to offer services there
- [X] You wish to block access due to security concerns
- [ ] Other     

Then the Firewall can be used to



## <a name="vpn-&-proxy-users"> VPN & Proxy users

