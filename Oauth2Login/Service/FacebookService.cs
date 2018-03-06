using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Runtime.Serialization;
using System.Web;
using Newtonsoft.Json;
using Oauth2Login.Client;
using Oauth2Login.Core;

namespace Oauth2Login.Service
{
    public class FacebookService : BaseOauth2Service
    {
        private static string _oauthUrl = "";

        public FacebookService(AbstractClientProvider oClient) : base(oClient) { }

        public override string BeginAuthentication()
        {
            var qstring = QueryStringBuilder.Build(
                "client_id", _client.ClientId,
                "redirect_uri", _client.CallBackUrl,
                "scope", _client.Scope,
                "state", "",
                "display", "popup"
                );

            _oauthUrl = "https://www.facebook.com/dialog/oauth?" + qstring;

            return _oauthUrl;
        }

        public override string RequestToken(HttpRequestBase request)
        {
            var code = request.Params["code"];
            if (String.IsNullOrEmpty(code))
                return OAuth2Consts.ACCESS_DENIED;

            string tokenUrl = string.Format("https://graph.facebook.com/oauth/access_token?");
            string postData = QueryStringBuilder.Build(
                "client_id", _client.ClientId,
                "redirect_uri", _client.CallBackUrl,
                "client_secret", _client.ClientSecret,
                "code", code
            );

            string responseJson = HttpPost(tokenUrl, postData);
            responseJson = responseJson.Replace("=", "\":\"").Replace("&", "\",\"");

            if (responseJson.Substring(0, 1) != "{")
                responseJson = "{\"" + responseJson + "\"}";
            return JsonConvert.DeserializeAnonymousType(responseJson, new { access_token = "" }).access_token;
        }

        public override void RequestUserProfile()
        {
            var fields = "id,email,name,first_name,last_name,link,gender,locale,timezone,verified";
            var profileUrl = "https://graph.facebook.com/me?fields="+ fields +"&access_token=" + _client.Token;

            string result = HttpGet(profileUrl);

            ParseUserData<FacebookUserData>(result);
        }
    }

    public class FacebookUserData : BaseUserData
    {
        public FacebookUserData() : base(ExternalAuthServices.Facebook) { }

        public string id { get; set; }
        public string email { get; set; }
        public string name { get; set; }
        public string first_name { get; set; }
        public string last_name { get; set; }
        public string link { get; set; }
        public string gender { get; set; }
        public string picture { get; set; }
        public string locale { get; set; }
        public double timezone { get; set; }
        public bool verified { get; set; }

        // override
        public override string UserId { get { return id; } }
        public override string Email { get { return email; } }
        public override string FullName { get { return name; } }

        public override string PhoneNumber { get { return null; } }
    }
}