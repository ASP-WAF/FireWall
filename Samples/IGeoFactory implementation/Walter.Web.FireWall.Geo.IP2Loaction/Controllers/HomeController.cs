using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Net;
using System.Threading.Tasks;
using Walter.Web.FireWall.Geo.IP2Loaction.Models;

namespace Walter.Web.FireWall.Geo.IP2Loaction.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        IPageRequest _request;
        private readonly IFireWall _fireWall;

        public HomeController(ILogger<HomeController> logger, IPageRequest request, IFireWall fireWall)
        {
            _logger = logger;
            _request = request;
            _fireWall = fireWall;
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new WhoisQuery();
            model.IPAddress = _request.IPAddress.ToString();

            return View(model);
        }


        [HttpPost, AutoValidateAntiforgeryToken]
        //reject those that try and refresh the application to see if it will fail
        [Walter.Web.FireWall.Annotations.PageRefresh(ignoreRefreshCount: 1
                                                    , maximumAttemptsInSeconds: 6
                                                    , blockDurationInSeconds: 6
                                                    , redirectToController: "home"
                                                    , redirectToAction: "index"
                                                    , id: (int)Filters.FireWallGuardActions.RejectRefreshViolations)]
        public async Task<IActionResult> Query(WhoisQuery model)
        {

            if (!ModelState.IsValid)
                RedirectToAction(nameof(Index));

            var result = new WhoisQueryResult() { IPAddress = model.IPAddress };

            if (IPAddress.TryParse(model.IPAddress, out var address))
            {
                result.Whois = await _fireWall.WhoisAsync(address).ConfigureAwait(false);
            }
            else
            {
                result.IPAddress = _request.IPAddress.ToString();

                //it will already know the ISP from the first time it was loaded
                result.Whois = _request.GetISP();
                ModelState.AddModelError("IP address", "The IP address is not valid");
            }

            return View(model);
        }
        /// <summary>
        /// Allow the user to get 5 visits to the block page 
        /// </summary>
        /// <returns></returns>
        [Walter.Web.FireWall.Annotations.Ignore(skip: Filters.FireWallGuardActions.ALL, skipCount: 5)]
        public IActionResult Blocked()
        {

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
