using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Net;
using Walter.BOM.Geo;
using Walter.Net;
using Walter.Net.Networking;
using Walter.Web.FireWall.Geo.IP2Loaction.Models;

namespace Walter.Web.FireWall.Geo.IP2Loaction.Infrastructure
{


    public class IP2LocationGeoFactory : IGeoFactory
    {
        //update this with your key or provide the key via 
        const string countryCode = "https://api.ip2location.com/v2/?ip={0}&key={1}";

        //not used as returns a random number
        //const string creditsCheck = "https://api.ip2location.com/v2/?key=demo&check=1";
        const GeoLocation _home = GeoLocation.Luxembourg;

        int _creditsUsed = -1;
        int _creditsLeft = -1;
        string _key;
        private readonly IFireWallConfig _config;
        private readonly IMemoryCache _memory;
        private readonly ILogger _logger;
        private readonly MemoryCacheEntryOptions _memoryCacheEntryOptions;
        private readonly JsonSerializerSettings _settings;
        private readonly WafWebClient _client;
        private readonly bool _debugLoggingOn;
        public IP2LocationGeoFactory(IFireWallConfig config, IMemoryCache memory, IConfiguration configuration = null, ILoggerFactory loggerFactory = null)
        {
            _settings = new JsonSerializerSettings() { ConstructorHandling = ConstructorHandling.AllowNonPublicDefaultConstructor };
            _config = config;
            _memory = memory;
            _logger = loggerFactory?.CreateLogger<IP2LocationGeoFactory>();
            _memoryCacheEntryOptions = config.Cashing.GeoLocation;
            _client = new Walter.Net.WafWebClient();

            //make it easy to test when no configuration then use demo
            _key = configuration?.GetValue<string>("IP2LocationKey") ?? "demo";

            //only generate debug logs if enabled making log processing more streamlined
            _debugLoggingOn = _logger?.IsEnabled(LogLevel.Debug) ?? false;
        }




        public bool IsBlocked(GeoLocation? geo)
        {
            if ( geo is null || geo.HasValue==false)
                return false;

            var blocked = _config.Geography.IsBlocked(geo.Value);
            if (_debugLoggingOn)
            {
                _logger?.Lazy().LogDebug(new EventId(-1, "IP2Location")
                    , "Request if Geography {geo} is blocked returned \"{flag}\""
                    , geo
                    , (blocked ? "block":"No issues")
                    );
            }

            return blocked;
        }

        public bool IsGeoBlocked(IPAddress address)
        {
            if (address is null)
            {
                throw new ArgumentNullException(nameof(address));
            }

            var result = !IsGeoWhiteListed(address) && IsBlocked(QueryLocation(address));

            if (_debugLoggingOn)
            {
                _logger?.Lazy().LogDebug(new EventId(-1, "IP2Location")
                    , "Request if Geography {geo} is blocked returned {flag}"
                    , address
                    , (result ? "ok" : "block")
                    );
            }

            return result;

        }

        public bool IsGeoWhiteListed(IPAddress address)
        {
            if (address is null)
            {
                throw new ArgumentNullException(nameof(address));
            }

            var found = _config.Geography.IsWhiteListed(address);

            if (_debugLoggingOn)
            {
                _logger?.Lazy().LogDebug(new EventId(-1, "IP2Location")
                    , "Request Is GeoWhiteListed {address} returned {flag}"
                    , address
                    , (found ? "ok" : "block")
                    );
            }

            return found;
        }


        /// <summary>
        /// Query the location of an IP 
        /// </summary>
        /// <param name="address">The IP to query</param>
        /// <returns>
        /// the location if found and the API is valid
        /// </returns>

        public GeoLocation QueryLocation(IPAddress address)
        {
            var location = GeoLocation.UnKnown;
            //there are several ways to avoid making redundant call when detecting on your network configuration and topography 
            if (address.IsLocalIpAddress() || address.IsInLocalSubnet() || address.Scope() != CommunicationScopes.WAN)
            {
                return _home;
            }

            var key = string.Concat("Ip2L", address.ToString());
            if (_memory.TryGetValue<Ip2LocationCoutyRequest>(key, out var data))
            {
                if (_debugLoggingOn)
                {
                    _logger?.Lazy().LogDebug(new EventId(-1, "IP2Location"), "Request for the location of {address} answered from memory with {location}"
                    , address
                    , data.Location
                    );
                }
                return data.Location;
            }


            if (_creditsLeft == 0)
            {
                _logger?.Lazy().LogWarning(eventId: new EventId(ERROR_CODES.NoMoreRequestsInIp2LocationAccount, "IP2Location"), "No more available request for GEO location with IP2Locations account for this 24 hour period, credits used:{creditsUsed}, Credits Left:{creditsLeft}", _creditsUsed, _creditsLeft);
            }


            //the web client keeps a audit log of all requests and request status
            string json = _client.Get(MakeUri(address));
            //get the last entry from the log, may not be the correct one
            var entry = _client.Requests[0];
            try
            {
                if (_client.IsSuccessStatusCode && json.IsValidJson<Ip2LocationCoutyRequest>(_settings, out data) && data.Location != GeoLocation.UnKnown)
                {
                    _memory.Set<Ip2LocationCoutyRequest>(key, data, options: _memoryCacheEntryOptions);
                    location = data.Location;
                }

                return location;
            }
            finally
            {
                if (entry.Status == HttpStatusCode.OK)
                {
                    if (_debugLoggingOn)
                    {
                        _logger?.Lazy().LogDebug(new EventId(-1, "IP2Location")
                                                , message: "Request for the location of {address} to IP2Location using {method} on {url} returns {status} after {roundTrip} Json returned:{json}"
                                                , address
                                                , entry.Method
                                                , entry.Url.AbsoluteUri
                                                , _client.StatusCode
                                                , _client.RoundTrip
                                                , json
                                                );
                    }
                }
                else
                {
                    _logger?.Lazy().LogCritical(new EventId(ERROR_CODES.API_FAILED, "IP2Location")
                                    , exception: _client.Exception
                                    , message: "Request for the location of {address} to IP2Location using {method} on {url} returns {status} after {roundTrip} Json returned:{json}"
                                    , address
                                    , entry.Method
                                    , entry.Url.AbsoluteUri
                                    , _client.StatusCode
                                    , _client.RoundTrip
                                    , json
                                    );
                }
            }

        }

        private Uri MakeUri(IPAddress address)
        {
            return new Uri(string.Format(countryCode, address.ToString(), _key)
                          , UriKind.Absolute);
        }

        public GeoLocation QueryProxy(IPAddress address)
        {
            _logger?.Lazy().LogInformation("Query proxy is not implemented");
            return GeoLocation.UnKnown;
        }


        public bool TryGetLocation(IPAddress remoteAddress, out GeoLocation location)
        {
            location = GeoLocation.UnKnown;

            try
            {
                location = QueryLocation(remoteAddress);
            }
            catch (Exception e)
            {
                _logger?.Lazy().LogError(eventId: new EventId(ERROR_CODES.EXCEPTION, "TryGetLocation"), e, "A {exception} exception was generated with message:{message}", e.GetType().Name, e.Message);
            }

            return location != GeoLocation.UnKnown;
        }
        public void SetOptions()
        {

        }

        public Walter.BOM.Geo.GeoLocation MapLocation2Country(string sampleJson)
        {
            if (string.IsNullOrEmpty(sampleJson))
            {
                throw new ArgumentException($"'{nameof(sampleJson)}' cannot be null or empty", nameof(sampleJson));
            }

            var data = JsonConvert.DeserializeObject<Ip2LocationCoutyRequest>(sampleJson);

            //up date accurate count of requests done
            lock (this)
            {
                if (_creditsUsed < data.CreditsUsed)
                {
                    _creditsUsed = data.CreditsUsed;
                    _creditsLeft = data.CreditsLeft;
                }
            }
            return data.Location;

        }
    }
}
