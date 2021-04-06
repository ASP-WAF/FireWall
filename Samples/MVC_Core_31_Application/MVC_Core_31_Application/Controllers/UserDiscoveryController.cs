using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Walter;
using Walter.BOM.ErrorCodes;
using Walter.Net.Networking;
using Walter.Web.FireWall;
using Walter.Web.FireWall.Annotations;
using Walter.Web.FireWall.Destinations.Email;
using Walter.Web.FireWall.Filters;
using Walter.Web.FireWall.Reporting;

namespace MVC_Core_31_Application.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserDiscoveryController : ControllerBase
    {
        private readonly ILogger<UserDiscoveryController> _logger;
        private readonly IFireWall _fireWall;
        private readonly IPageRequest _page;
        public UserDiscoveryController(ILogger<UserDiscoveryController> logger, IFireWall fireWall, IPageRequest page)
        {
            _logger = logger;
            _fireWall = fireWall;
            _page = page;
        }


        /// <summary>
        /// an API endpoint that can be called from an API endpoint and is protected using the firewall rule-set for 
        /// API Endpoints
        /// </summary>
        /// <remarks>
        /// there is also a Json version allowing you to automate monitoring
        /// </remarks>
        /// <returns>the text report of the firewall, </returns>
        [Ignore(skip: FireWallGuardActions.API_ENDPOINT_LAX)]
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


        /// <summary>
        /// Rout registered by the browser header so that browsers know that the reporting infrastructure exists
        /// </summary>
        /// <remarks>
        /// See header configuration in firewall options, this will catch any violations that are prevented or warned by the browser.
        /// this will only work for web applications that render html for browsers to use
        /// </remarks>
        /// <param name="model">the model as populated by the browser</param>
        /// <returns>OK</returns>
        [HttpPost]
        [Route(Links.CSP)]
        public IActionResult CSP(CSPModel model)
        {
            //lazy logging does not slow down the application as it is queued for later processing or ignored if A log level is not enabled
            _logger.Lazy().LogCritical(new EventId(1001, "Developer related issue")
                                      , "CSP Violation reported by {agent} on {path} on line {line}"
                                      , _page.User.UserAgent, model.BlockedUri, model.LineNumber);

            // record CSP violations reported by the browser and send it to all documentation interfaces including the email reporting used
            // by the sample
            var csp = new ContentSecurityPolicyViolation(_page, model);
            _fireWall.Enqueue(csp);
            if (Debugger.IsAttached)
            {
                //cause the debugger to brake on this line so you can see the error as it is reported
                Debugger.Break();
            }
            else
            {
                //Use the extension method that comes with the NuGet Package and send a email to the developers so that they can fix the violation
                _fireWall.SendEmail(EMailRoles.SecurityRelevant, "CSP violation detected", JsonConvert.SerializeObject(model, Formatting.Indented), false);
            }
            return Ok();
        }


        [HttpGet]
        [NoCache]
        [Route(Links.UserEndpointJavaScript)]
        [Ignore(Walter.Web.FireWall.Filters.FireWallGuardActions.EmbeddedResources)]
        [FireWallConfiguration(FireWallConfigurationElement.DiscoveryJavaScript)]
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
                    _logger?.Lazy().LogError("ValidateUser javascript generation failed for {Page}", _page.ToString());
                    javaScript = System.Text.UTF8Encoding.UTF8.GetBytes($"console.log('could not generate userValidation')");
                    return File(fileContents: javaScript, contentType: "text/javascript");
                }
            }
            catch (ArgumentException e)
            {
                _page.Exception = e;

                _fireWall.LogException<RunTimeErrors>(RunTimeErrors.ArgumentNullException, e, "Missing a configuration element or using wrong release for your deployment");
                var javaScript = System.Diagnostics.Debugger.IsAttached
                    ? System.Text.UTF8Encoding.UTF8.GetBytes($"console.log('could not generate userValidation due to {e.Message}')")
                    : System.Text.UTF8Encoding.UTF8.GetBytes($"//Validate log {DateTime.Now} for errors and update settings");
                return File(fileContents: javaScript, contentType: "text/javascript");
            }
            catch (Exception e)
            {
                _page.Exception = e;

                _fireWall.LogException<RunTimeErrors>(RunTimeErrors.ArgumentNullException, e, $"User type discovery will not work as good as it could please fix {e.Message}");
                var javaScript = System.Text.UTF8Encoding.UTF8.GetBytes($"console.log('could not generate userValidation due to {e.Message}')");
                return File(fileContents: javaScript, contentType: "text/javascript");
            }
            finally
            {
                _logger?.Lazy().LogInformation("ValidateUser called");
            }
        }

        [HttpPost]
        [Route(Links.BeaconPoint)]
        [CrossSite, Ignore(skip: FireWallGuardActions.ALL & ~FireWallGuardActions.RejectCrossSiteRequests)]
        [ModelFilter(associations: RequestersAssociations.InCurrentPage, generateIncident: false)]
        [FireWallConfiguration(FireWallConfigurationElement.Beacon)]
        public StatusCodeResult Beacon([FromBody] Beacon model)
        {
            if (!ModelState.IsValid)
            {
                _logger?.Lazy().LogWarning("beacon: failed has {errors} errors", ModelState.ErrorCount);
                return this.Ok();//no need to make a fuss
            }


            _fireWall.ModelIsValid(pageContext: _page, model: model, out var errors);
            if (errors.Sum(s => s.BlockingSeverityScore) < 100)
            {
                _fireWall.LogPageRequest(model, _page);
            }
            else
            {
                foreach (var error in errors)
                {
                    _logger?.Lazy().LogWarning("beacon: {warn}", error);
                }
            }
            return this.Ok();
        }

        [HttpPost]
        [Route(Links.IsUserEndpoint)]
        [CrossSite, Ignore(skip: FireWallGuardActions.ALL & ~FireWallGuardActions.RejectCrossSiteRequests)]
        [FireWallConfiguration(FireWallConfigurationElement.DiscoveryModel)]
        public StatusCodeResult UserDiscovery([FromBody] string json)
        {
            if (_page.TryLogDiscovery(json))
            {
                return Ok();
            }
            return this.BadRequest();
        }

        [HttpPost]
        [Route(Links.SiteMapEndPoint)]
        [CrossSite(useDefaultRedirect: false), Ignore(skip: FireWallGuardActions.ALL & ~FireWallGuardActions.RejectCrossSiteRequests)]
        [FireWallConfiguration(FireWallConfigurationElement.SiteMapModel)]
        public async Task<StatusCodeResult> SiteMap([FromBody] string json)
        {
            if (_page.TryLogSiteMap(json))
            {
                return Ok();
            }
            else
            {
                return BadRequest();
            }
        }

    }
}
