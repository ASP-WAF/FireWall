using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Walter;
using Walter.BOM.ErrorCodes;
using Walter.Web.FireWall;
using Walter.Web.FireWall.Annotations;
using Walter.Web.FireWall.Filters;
using Walter.Web.FireWall.Reporting;

namespace Nop.Web.Controllers
{
    public class FireWallController : Controller
    {

        private readonly ILogger<FireWallController> _logger;
        IPageRequest _page;
        IFireWall _fireWall;
        public FireWallController(IPageRequest page, IFireWall fireWall,ILogger<FireWallController> logger=null)
        {
            _page = page;
            _fireWall = fireWall;
            _logger = logger;
        }
        
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

        [DisableFirewall]
        [Route(Links.CSP)]
        [HttpPost]
        public StatusCodeResult ReportContentSecurityPolicyViolations(CSPModel report)
        {
            _logger.Lazy().LogError("CSP Violation Blocked Uri {url}, please validate your application for effective directive {directive} on line {line} ", report.BlockedUri,report.EffectiveDirective, report.LineNumber);
            _fireWall.Enqueue(new ContentSecurityPolicyViolation(_page, report));
            return Ok();
        }


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

        [HttpPost]
        [Route(Links.BeaconPoint)]        
        [CrossSite(useDefaultRedirect: false)]
        [Ignore(skip: FireWallGuardModules.ALL & ~FireWallGuardModules.RejectCrossSiteRequests)]
        public StatusCodeResult Beacon(string model)
        {
            if (!string.IsNullOrEmpty(model))
            {
                var beacon = JsonConvert.DeserializeObject<Beacon>(model);
                _fireWall.ModelIsValid(pageContext: _page, model: beacon, out var errors);
                if (errors.Sum(s => s.BlockinSeverityScore) < 100)
                {
                    _fireWall.LogPageRequest(beacon, _page);
                }
                else
                {
                    foreach (var error in errors)
                    {
                        _logger?.LogWarning("beacon: {warn}", error);
                    }
                }
            }
            return this.Ok();
        }

        [HttpPost]
        [Route(Links.IsUserEndpoint)]
        [CrossSite(useDefaultRedirect: false)]
        [Ignore(skip: FireWallGuardModules.ALL & ~FireWallGuardModules.RejectCrossSiteRequests)]
        public StatusCodeResult UserDiscovery([FromBody] Discovery model)
        {
            if (model is null)
            {
                _logger?.LogInformation("user discovery called but the model field or data types are not compatible, please wait, update the model to fix the users discovery javascript");
                return this.NoContent();
            }
            else
            {
                _fireWall.ModelIsValid(pageContext: _page, model: model, out var errors);
                if (errors.Count==0 || (errors.Count>0 && errors.Sum(s => s.BlockinSeverityScore) < 100))
                {
                    _fireWall.LogPageRequest(model, _page);
                    return Ok();
                }
                else
                {
                    _logger?.LogWarning("Assume an attempt was made to send a tampered model to {url} due to it achieving an error score of {score}", _page.OriginalUrl.AbsoluteUri, errors.Sum(s => s.BlockinSeverityScore));
                    if (errors.Sum(s => s.BlockinSeverityScore) > 100)
                    {
                        var fwu = _page.User.AsFirewallUser();
                        using (var scope = _logger?.BeginScope<string>($"User {fwu.Id} from {fwu.IPAddress} tampered with the model send back to {Links.IsUserEndpoint} and triggered {errors.Count} warnings"))
                        {
                            for (var i = 0; i < errors.Count; i++)
                            {
                                _logger?.LogWarning("incident:{count} reason:{reason} context:{context} weight:{weight}", i + 1, errors[i].Reason, errors[i].BlockingContext, errors[i].BlockinSeverityScore);
                            }
                        }
                        //tamper detected so return a 404
                        return this.NotFound();
                    }
                    //model data is not valid, could be tampered but could also just be not containing required values
                    return this.BadRequest();
                }
            }
        }

        [HttpPost]
        [Route(Links.SiteMapEndPoint)]
        [CrossSite(useDefaultRedirect: false)]
        [Ignore(skip: FireWallGuardModules.ALL & ~FireWallGuardModules.RejectCrossSiteRequests)]
        public async Task<StatusCodeResult> SiteMap([FromBody] SiteMapDiscovery model)
        {
            _logger.Lazy().LogInformation("Url discovery called");

            if (model is null)
                return NoContent();
            else
            {
                _fireWall.ModelIsValid(pageContext: _page, model: model, out var errors);

                if (errors.Sum(s => s.BlockinSeverityScore) < 100 && _page.RootPage != null)
                {
                    _logger.Lazy().LogDebug("Url discovery send to firewall");
                    await _fireWall.LogSiteMapAsync(page: _page, model: model).ConfigureAwait(false);
                }
                return Ok();
            }
        }
    

    }
}
