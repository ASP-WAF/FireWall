using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using MVC_Core_31_Application.Models;
using Walter.Web.FireWall;
using Walter.Web.FireWall.Annotations;

namespace MVC_Core_31_Application.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IPageRequest _page;
        public HomeController(ILogger<HomeController> logger, IPageRequest page)
        {
            _logger = logger;
            _page = page;
        }

        public IActionResult Index()
        {
            return View(_page);
        }

        [Users(UserTypes.IsHuman,redirectToController:"home",redirectAction:"Error")]
        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        [DisableFirewall]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
