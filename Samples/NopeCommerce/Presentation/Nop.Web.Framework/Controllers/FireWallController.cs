using System;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Walter.Web.FireWall;
using Walter.Web.FireWall.Reporting;

namespace Nop.Web.Framework.Controllers
{
    
    //[Nop.Web.Framework.Mvc.Filters.AuthorizeAdmin]
    [ApiController]
    [Route("api/[controller]")]
    public class FireWallController : ControllerBase
    {
        private readonly ILogger<FireWallController> _logger;
        private readonly IFireWall _fireWall;
        private readonly IPageRequest _page;
        public FireWallController(IFireWall fireWall,IPageRequest page, ILogger<FireWallController> logger=null)
        {
                _logger = logger;
                _fireWall = fireWall;
                _page = page;
            }

        [HttpGet]       
        public string Get()
        {
            _logger?.LogInformation("Get Health with admin protection from nope");

            var list = new StringBuilder();

            list.AppendLine($"Firewall version: {_fireWall.FirewallModuleVersion} status {_fireWall.State} license {_fireWall.License.LicenseKey.Domain.DomainUrl}: {_fireWall.License.LicenseKey.LicenseLevel}");
            list.AppendLine("---------------------------------------------------");
            if (_page.User.IsAuthenticated)
            {
                list.AppendLine(_fireWall.Report(ReportTypes.ALL));
            }
            else
            {
                list.AppendLine(_fireWall.Report(ReportTypes.Details));
            }
            list.AppendLine("---------------------------------------------------");
            return list.ToString();
        }
    }
}