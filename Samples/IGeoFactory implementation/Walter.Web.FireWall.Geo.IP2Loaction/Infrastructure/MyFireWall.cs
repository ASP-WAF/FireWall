using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using Walter.Web.FireWall.Models;

namespace Walter.Web.FireWall.Geo.IP2Loaction.Infrastructure
{
    /// <summary>
    /// you can inject your own firewall by basing your firewall on the FireWallBased class.
    /// </summary>
    /// <remarks>
    /// When overriding the firewall class you have the possibility to interact with requests and incidents at a very early stage    /// 
    /// </remarks>
    public class MyFireWall : FireWallBase
    {
        ILogger _logger;
        public MyFireWall(IServiceProvider serviceProvider, IMemoryCache memory, ILoggerFactory loggerFactory)
            : base(serviceProvider: serviceProvider, loggerFactory: loggerFactory, memoryCache: memory)
        {
            _logger = loggerFactory?.CreateLogger<MyFireWall>();

            base.OnCaughtExceptiont += MyFireWall_OnCaughtExceptiont;
            base.OnIncident += MyFireWall_OnIncident;
            base.OnPhishyRequest += MyFireWall_OnPhishyRequest;
            base.OnUserTypeChange += MyFireWall_OnUserTypeChange;
            base.OnGuardAction += MyFireWall_OnGuardAction;
            base.OnResourceRequested += MyFireWall_OnResourceRequested;
            base.Trigger_OnFireWallCreated(this);


            var data = KnownLinks.EndpointsInPath("*.zip", "*.pdf");
            foreach (var item in data)
            {
                item.AddHock = null;
                item.NoValidate = Filters.FireWallGuardActions.RejectAddHockRequests | Filters.FireWallGuardActions.RejectCrossSiteRequests;

            }
            data = KnownLinks.EndpointsInPath("*.css", "*.png", "*.jpg", "*.js");
            foreach (var item in data)
            {
                if (item.IsFile)
                {
                    //disable the firewall for static files that match the pattern
                    item.FirewallDisabled = true;
                }
            }




        }

        private void MyFireWall_OnResourceRequested(object sender, EventArguments.PageCreatedEventArgs e)
        {

            _logger.LogDebug("{Request} detected by the firewall", e.Request);

        }

        /// <summary>
        /// trigger on each request the firewall would like to block
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void MyFireWall_OnGuardAction(object sender, Walter.Web.FireWall.EventArguments.GuardActionEventArgs e)
        {
            _logger.Lazy().LogInformation(eventId: new EventId(Line(), Method())
                                        , message: "Page {Page} generated a {action} recommendation"
                                        , e.Page
                                        , e.Action);

            //allow the firewall to block a request
            e.AllowGuardAction = true;

            if (Debugger.IsAttached)
            {
                //pause the application when debugged to allow you to use debugger to inspect state
                Debugger.Break();
            }
        }

        /// <summary>
        /// Trigger each time the firewall detected a user type change
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void MyFireWall_OnUserTypeChange(object sender, Walter.Web.FireWall.EventArguments.UserTypeChangedEventArgs e)
        {
            _logger.Lazy().LogInformation(eventId: new EventId(Line(), Method())
                                         , message: "Module {Module} detected a user {user} type change from {fromType} to {toType} on {path}"
                                         , e.Module
                                         , e.User
                                         , e.OriginalType
                                         , e.NewType
                                         , e.Url.LocalPath
                                         );
            e.Allow = true;
            if (Debugger.IsAttached)
            {
                //pause the application when debugged to allow you to use debugger to inspect state
                Debugger.Break();
            }

        }

        /// <summary>
        /// Triggered each time a user does something he should not be doing
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void MyFireWall_OnPhishyRequest(object sender, Walter.Web.FireWall.EventArguments.PhishyRequestEventArgs e)
        {
            var fireWallUser = e.Request.User.AsFirewallUser();

            _logger.Lazy().LogInformation(eventId: new EventId(Line(), Method())
                                         , message: "A request by user {fireWallUser} with a search engine status of {SearchEngine} tries to access a non existing resource = {method} {path} via referer = {referer}."
                                         , fireWallUser
                                         , e.Request.User.IsSearchEngine
                                         , e.Request.Method
                                         , e.Request.OriginalUrl.PathAndQuery
                                         , e.Request.PreviousPage?.PathAndQuery ?? e.Request.Referrer?.PathAndQuery ?? "un-known referer"
                                         );

            //set create incident to true if the link does not exist, normally this would be a penetration attempt
            //e.CreateIncident = false;

            e.CreateIncident = e.SiteMapSearch == SiteMapSearchResult.NotFound && e.Request.User.IsSearchEngine == SearchEngine.NotSure;


            if (Debugger.IsAttached)
            {
                //pause the application when debugged to allow you to use debugger to inspect state
                Debugger.Break();
            }
        }

        
        /// <summary>
        /// Triggered when the firewall would like to generate an incident based on the users activity
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void MyFireWall_OnIncident(object sender, Walter.Web.FireWall.EventArguments.FireWallIncidentEventArgs e)
        {

            /* 
             * the Guard will have generated a indecent report in the ILogger instance at Walter.Web.FireWall.Guard
             * see logger settings at appsettings.json
             * 
             * you can configure the log level for incidents at see:
             * RulesConfig.Default.IncidentLogLevel
             * RulesConfig.Default.IncidentEventId
             * 
             * Stack entry contains all violations detected on this one request
             */

            var si = e.StackEntry;

            _logger?.Lazy().LogInformation(eventId: new EventId(Line(), Method())
                                       , message: "{ControlledBy}: Page Nr {Nr} {method} {path} triggered rule {RuleNr} due to {Reason} will not generate an incident as UserCode has taken responsibility for the request from {country}"
                                       , si.ControlledBy
                                       , e.Page.SessionPageGroupNumber
                                       , e.Page.Method
                                       , e.Page.OriginalUrl.AbsolutePath
                                       , si.RuleNr
                                       , si.Reason
                                       , Walter.BOM.Geo.GeoLocationMapping.GetCountryName(e.Page.Country ?? Walter.BOM.Geo.GeoLocation.UnKnown)
                                       );

            //data contains values that caused the incident to trigger
            //you can use these values to adjust your rule, or ignore errors 
            foreach (var entry in e.Data)
            {
                _logger?.Lazy().LogInformation(eventId: new EventId(Line(), Method()), message: "{Type}={Data}", entry.Key, entry.Value);
            }

            //look at the e.Page.Incidents() to access any other incidents the user has generated
            //also look at the e.Page.BreadCrumbs to view previous requests 
            e.AllowRaiseIncident = true;

            // It's no big deal if the user refreshes the page
            if (e.Page.HasViolated(Filters.FireWallGuardActions.RejectRefreshViolations))
            { 
                e.AllowRaiseIncident = false;
            }

            if (Debugger.IsAttached)
            {
                //pause the application when debugged to allow you to use debugger to inspect state
                Debugger.Break();
            }
        }

        /// <summary>
        /// fired when the firewall or processing firewall data caused an exception
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void MyFireWall_OnCaughtExceptiont(object sender, Walter.Web.FireWall.EventArguments.ExceptionCaughtEventArgs e)
        {
            //set it to true to not throw the exception
            e.ExceptionHandled = true;

            if (Debugger.IsAttached)
            {
                //pause the application when debugged
                Debugger.Break();
            }
            _logger.Lazy().LogInformation(eventId: new EventId(Line(), Method()), exception: e.Page.Exception, "Processing Request {Page} triggered {processed} exception of {type}"
                    , e.Page
                    , e.ExceptionHandled ? "handled" : "un-handled"
                    , e.Page.Exception.GetType().Name
                    );
        }

        internal static int Line([CallerLineNumber] int line = -1) => line;
        internal static string Method([CallerMemberName] string method = "") => method;
    }
}
