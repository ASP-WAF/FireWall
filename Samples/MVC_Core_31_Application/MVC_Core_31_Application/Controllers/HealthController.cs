using Microsoft.AspNetCore.Mvc;
using Walter.Web.FireWall;
using Walter.Web.FireWall.Reporting;

namespace MVC_Core_31_Application.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HealthController : ControllerBase
    {
        private readonly IFireWall _fireWall;

        public HealthController(IFireWall firewall)
        {
            _fireWall = firewall;
        }

        [HttpGet]
        [Produces("text/plain")]

        public string Index()
        {            
            return _fireWall.Report(ReportTypes.ALL);
        }

    }
}
