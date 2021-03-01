using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Walter.Net.Networking;
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
            var model= _request.GetISP();
            return View(model);
        }

        
        [HttpPost,AutoValidateAntiforgeryToken]
        //reject those that try and refresh the application to see if it will fail
        [Walter.Web.FireWall.Annotations.PageRefresh(ignoreRefreshCount:1
                                                    , maximumAttemptsInSeconds:6
                                                    , blockDurationInSeconds:6
                                                    ,redirectToController:"home"
                                                    ,redirectToAction: "index"
                                                    , id:(int)Filters.FireWallGuardModules.RejectRefreshViolations)]
        public async Task<IActionResult> Index(string ip)
        {
            IWhois model;

            if (IPAddress.TryParse(ip, out var address))
            {
                model = await _fireWall.WhoisAsync(address).ConfigureAwait(false);                
            }
            else
            {
                //it will already know the ISP from the first time it was loaded
                model = _request.GetISP();
                ModelState.AddModelError("IP address", "The IP address is not valid");
            }

            return View(model);
        }
        /// <summary>
        /// Allow the user to get 5 visits to the block page 
        /// </summary>
        /// <returns></returns>
        [Walter.Web.FireWall.Annotations.Ignore(skip:Filters.FireWallGuardModules.ALL, skipCount:5) ]
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
