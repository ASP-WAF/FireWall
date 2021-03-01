using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Walter.Web.FireWall.Geo.IP2Loaction.Infrastructure
{
    public class ERROR_CODES
    {
        
        public static int NoMoreRequestsInIp2LocationAccount =1;
        public static int EXCEPTION=101;

        public static int API_FAILED { get; internal set; }
    }
}
