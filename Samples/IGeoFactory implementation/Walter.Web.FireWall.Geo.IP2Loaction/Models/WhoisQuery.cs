using System.ComponentModel.DataAnnotations;
using Walter.Net.Networking;

namespace Walter.Web.FireWall.Geo.IP2Loaction.Models
{
    public class WhoisQuery
    {
        [Required]
        public string IPAddress { get; set; }

    }

    public class WhoisQueryResult : WhoisQuery
    {

        //hide this from the form
        public IWhois Whois { get; set; }
    }
}
