using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Walter;
using Walter.BOM.ErrorCodes;
using Walter.Web.FireWall;
using Walter.Web.FireWall.Annotations;
using Walter.Web.FireWall.Filters;

namespace Net6_WebApplication.Controllers
{
    public class FireWallController : Controller
    {
        private readonly IPageRequest _page;
        private readonly IFireWall _fireWall;
        private readonly ILogger<FireWallController> _logger;

        public FireWallController(IPageRequest pageContext, IFireWall fireWall, ILogger<FireWallController> logger = null)
        {
            _page = pageContext;
            _fireWall = fireWall;
            _logger = logger;
        }

        [HttpPost]
        [Route(Links.CSPViolation)]
        public IActionResult CSP(CSPModel model)
        {

            var csp = new ContentSecurityPolicyViolation(_page, model);
            _fireWall.Enqueue(csp);
            return Ok();
        }

 
        [Ignore]
        public StatusCodeResult ReportContentSecurityPolicyViolations(ContentSecurityPolicyViolation report)
        {
            _fireWall.Enqueue(report);
            return Ok();
        }

        [HttpGet]
        [Route(Links.UserEndpointJavaScript)]
        [Ignore(Walter.Web.FireWall.Filters.FireWallGuardModules.EmbeddedResources)]
        [NoCache]
        public FileContentResult ValidateUser(string id = null)
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

        [HttpPost, Route(Links.BeaconPoint)]
        [CrossSite, Ignore(skip: FireWallGuardModules.ALL & ~FireWallGuardModules.RejectCrossSiteRequests)]
        [ModelFilter(associations: RequestersAssociations.InCurrentPage
                   , generateIncident: false
                   , pageGroupPropertyName: Walter.Web.FireWall.Beacon.PageRequestGroupIdModelCode)]
        public StatusCodeResult Beacon(string model)
        {
            if (!ModelState.IsValid)
            {
                _logger?.Lazy().LogWarning("beacon: failed has {errors} errors", ModelState.ErrorCount);
                return this.Ok();//no need to make a fuss
            }

            if (!string.IsNullOrEmpty(model))
            {
                var beacon = Newtonsoft.Json.JsonConvert.DeserializeObject<Beacon>(model);
                _fireWall.ModelIsValid(pageContext: _page, model: beacon, out var errors);
                if (errors.Sum(s => s.BlockinSeverityScore) < 100)
                {
                    _fireWall.LogPageRequest(beacon, _page);
                }
                else
                {
                    foreach (var error in errors)
                    {
                        _logger?.Lazy().LogWarning("beacon: {warn}", error);
                    }
                }
            }
            return this.Ok();
        }

        [HttpPost]

        [Route(Links.IsUserEndpoint)]
        [CrossSite, Ignore(skip: FireWallGuardModules.ALL & ~FireWallGuardModules.RejectCrossSiteRequests)]
        [ModelFilter(Associations = RequestersAssociations.InCurrentPage, GenerateIncident = false)]
        public StatusCodeResult UserDiscovery([FromBody] Discovery model)
        {
            if (model is null)
            {
                _logger?.Lazy().LogInformation("user discovery called but the model field or data types are not compatible, please wait, update the model to fix the users discovery javascript");
                return this.NoContent();
            }
            else
            {
                _fireWall.ModelIsValid(pageContext: _page, model: model, out var errors);
                if (errors.Sum(s => s.BlockinSeverityScore) < 100)
                {
                    _fireWall.LogPageRequest(model, _page);
                    return Ok();
                }
                else
                {
                    _logger?.Lazy().LogWarning("An attempt was made to send a tampered model to {url}", _page.OriginalUrl.AbsoluteUri);
                    if (errors.Sum(s => s.BlockinSeverityScore) > 100)
                    {
                        var fwu = _page.User.AsFirewallUser();
                        using (var scope = _logger?.BeginScope<string>($"User {fwu.Id} from {fwu.IPAddress} tampered with the model send back to {Links.IsUserEndpoint} and triggered {errors.Count} warnings"))
                        {
                            for (var i = 0; i < errors.Count; i++)
                            {
                                _logger?.Lazy().LogWarning("incident:{count} reason:{reason} context:{context} weight:{weight}", i + 1, errors[i].Reason, errors[i].BlockingContext, errors[i].BlockinSeverityScore);
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

        [HttpPost, Route(Links.SiteMapEndPoint)]
        [CrossSite(useDefaultRedirect: false), Ignore(skip: FireWallGuardModules.ALL & ~FireWallGuardModules.RejectCrossSiteRequests)]
        [ModelFilter(Associations = RequestersAssociations.InCurrentPage, GenerateIncident = false)]
        public StatusCodeResult SiteMap([FromBody] SiteMapDiscovery model)
        {
            _logger?.Lazy().LogInformation("Url SiteMapDiscovery called ");

            //return await base.SiteMap(model);
            if (model is null)
                return NoContent();
            else
            {
                //The firewall will use predictive navigation for user as well as use it in web-statistics to show choices made by the user
                _fireWall.LogSiteMap(_page, model);
                return Ok();
            }
        }
    }
}
