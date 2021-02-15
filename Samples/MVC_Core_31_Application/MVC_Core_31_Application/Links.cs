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
}
