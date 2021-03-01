using Newtonsoft.Json;

namespace Walter.Web.FireWall.Geo.IP2Loaction.Models
{
    public class Ip2LocationCoutyRequest
    {

       [JsonConstructor]

        private Ip2LocationCoutyRequest(string country_code, int credits_consumed)
        {
            CountryCode = country_code;
            CreditsUsed = credits_consumed;
        }

        /// <summary>
        /// country code returned belonging to IP address
        /// </summary>
        [JsonProperty("country_code")]
        public string CountryCode { get; private set; }

        /// <summary>
        /// IP 2 locations credits used on this request
        /// </summary>
        [JsonProperty("credits_consumed")]
        public int CreditsUsed { get; private set; }

        /// <summary>
        /// demo account has 20 requests a day
        /// </summary>
        [JsonIgnore]
        public int CreditsLeft
        {
            get
            {
                return 20 - CreditsUsed;
            }

        }

        /// <summary>
        /// get the location belonging to this request
        /// </summary>
        [JsonIgnore]
        public Walter.BOM.Geo.GeoLocation Location
        {
            get {
                if (Walter.BOM.Geo.GeoLocationMapping.TryGetValue(CountryCode, out var location))
                    return location;

                return Walter.BOM.Geo.GeoLocation.UnKnown;

            }
        }
    }
}
