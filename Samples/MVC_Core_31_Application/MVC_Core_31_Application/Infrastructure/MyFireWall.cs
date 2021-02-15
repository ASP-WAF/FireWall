using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using Walter;
using Walter.Web.FireWall;

namespace MVC_Core_31_Application.Infrastructure
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

            base.Trigger_OnFireWallCreated(this);
        }

        internal static int Line([CallerLineNumber] int line = -1) => line;
        internal static string Method([CallerMemberName] string method = "") => method;
        // Summary:
        //     Event triggered when the Firewall caught an exception during the execution of
        //     a IPageRequest
        //
        // Remarks:
        //     A popular way to hack a site is to crash it to bring it down or to see what happens.
        //     This event allows you to except the exception and manage how to deal with it
        //     as well as access the page request and generate a blocking incident Walter.Web.FireWall.IPageRequest.RenderThenBlock(Walter.Web.FireWall.RuleEngine.Rules.UserBlockingRule,System.String,System.TimeSpan,System.Uri)
        //     or Walter.Web.FireWall.IPageRequest.Block(Walter.Web.FireWall.RuleEngine.Rules.UserBlockingRule,System.String,System.TimeSpan,System.Uri)
        //     on details how to do this.
        //     A positive side effect is that you are able to intercept exceptions and deal
        //     with them as they happen without spoiling the users experience
        private void MyFireWall_OnCaughtExceptiont(object sender, Walter.Web.FireWall.EventArguments.ExceptionCaughtEventArgs e)
        {
            if (Debugger.IsAttached)
            {

                //pause the application when debugged
                Debugger.Break();
            }
            _logger.Lazy().LogInformation(eventId: new EventId(Line(), Method()), exception: e.Page.Exception, " Request {Page} triggered {} exception {type}"
                    , e.Page
                    , e.ExceptionHandled ? "handled" : "un-handled"
                    , e.Page.Exception.GetType().Name
                    );
        }


    }
}
