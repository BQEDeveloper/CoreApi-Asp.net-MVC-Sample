using System;
using System.Collections.Generic;
using System.Web.Mvc;
using BQE.Core.OAuth2.SampleMVCApp.DotNet.Models;
using Newtonsoft.Json;
using System.Configuration;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Web;
using System.Web.UI;

namespace BQE.Core.OAuth2.SampleMVCApp.DotNet.Controllers
{
    public class CoreOAuth2Controller : Controller
    {
        // client configuration
        static string redirectURI = ConfigurationManager.AppSettings["redirectURI"];
        static string discoveryURI = ConfigurationManager.AppSettings["discoveryURI"];
        static string clientID = ConfigurationManager.AppSettings["clientID"];
        static string Secret = ConfigurationManager.AppSettings["Secret"];
        static string coreIdentityUrl = ConfigurationManager.AppSettings["coreIdentityUrl"];
        static string coreBaseUrl = ConfigurationManager.AppSettings["coreBaseUrl"];
        static string logPath = ConfigurationManager.AppSettings["coreMessageLogPath"];


        static string scopeValConnectCore = System.Uri.EscapeDataString(ConfigurationManager.AppSettings["scopeValConnectCore"]);
        static string scopeValOpenId = System.Uri.EscapeDataString(ConfigurationManager.AppSettings["scopeValOpenId"]);
        static string scopeValSIWC = System.Uri.EscapeDataString(ConfigurationManager.AppSettings["scopeValSignInWithCore"]);

        //Discovery Data
        static string authorizationEndpoint;
        static string tokenEndpoint;
        static string userinfoEndPoint;
        static string revokeEndpoint;
        static string issuerUrl;
        static string jwksEndpoint;
        static string mod;
        static string expo;

        string code = "";

        string incoming_state = "";
        string companyId = "";


        public ActionResult Index()
        {
            if (Session["accessToken"] == null)
            {
                //connect.Visible = true;
                //disconnectCore.Visible = false;
                //lblConnected.Visible = false;
                //signInwithBQE.Visible = false;

                ViewBag.ShowConnect = true;
                ViewBag.ShowDisconnectCore = false;
                ViewBag.ShowLabelConnected = false;
                ViewBag.ShowSignInwithBQE = false;



                if (Request.QueryString.Count > 0)
                {
                    ViewBag.ClosePopup = "true";

                    List<string> queryKeys = new List<string>(Request.QueryString.AllKeys);
                    // Check for errors.
                    if (queryKeys.Contains("error") == true)
                    {
                        LogMessage(String.Format("OAuth authorization error: {0}.", Request.QueryString["error"].ToString()));
                        return View();
                    }
                    if (queryKeys.Contains("code") == false || queryKeys.Contains("state") == false)
                    {
                        LogMessage("Malformed authorization response.");
                        return View("Index");
                    }

                    //extracts the state
                    if (Request.QueryString["state"] != null)
                    {
                        incoming_state = Request.QueryString["state"].ToString();
                        if (Session["CSRF"] != null)
                        {
                            //match incoming state with the saved State in your DB from doOAuth function and then execute the below steps
                            if (Session["CSRF"].ToString() == incoming_state)
                            {
                                //extract companyId is scope is for ConnectToCore or Get App Now
                                //SIWC will not return companyId
                                if (Request.QueryString["companyId"] != null)
                                {
                                    companyId = Request.QueryString["companyId"].ToString();
                                    Session["companyId"] = companyId;
                                }

                                //extract the code
                                if (Request.QueryString["code"] != null)
                                {
                                    code = Request.QueryString["code"].ToString();
                                    LogMessage("Authorization code obtained.");

                                    //start the code exchange at the Token Endpoint.
                                    //this call will fail with 'invalid grant' error if application is not stopped after testing one button click flow as code is not renewed
                                    exchangeCode(code, redirectURI, companyId);
                                    //return RedirectToAction("Index");
                                    //Response.Redirect(Request.RawUrl.Replace(Request.Url.Query, ""));
                                    /*output("Access token obtained.");
                                    Session["accessToken"] = code;

                                    //get userinfo
                                    //This will work only for SIWC and Get App Now(OpenId) flows
                                    //Since ConnectToCore flow does not has the required scopes, you will get exception.
                                    //Here we will handle the exeception and then finally make Core api call
                                    //In your code, based on your workflows/scope, you can choose to not make this call
                                    UserProfile userdata = getUserInfo(code, "");*/

                                }
                            }
                            else
                            {
                                LogMessage("Invalid State");

                                Session.Clear();
                                Session.Abandon();
                            }
                        }

                    }

                }



            }
            else if (Session["callMadeBy"].ToString() == "ConnectToCore")
            {
                //connect.Visible = false;
                //disconnectCore.Visible = true;
                //signInwithBQE.Visible = false;

                ViewBag.ShowConnect = false;
                ViewBag.ShowDisconnectCore = true;
                ViewBag.ShowSignInwithBQE = false;
                //Disconnect();
            }
            else if (Session["callMadeBy"].ToString() == "SIWC" || Session["callMadeBy"].ToString() == "OpenId")
            {
                //connect.Visible = false;
                //disconnectCore.Visible = false;
                //signInwithBQE.Visible = true;

                ViewBag.ShowConnect = false;
                ViewBag.ShowDisconnectCore = false;
                ViewBag.ShowSignInwithBQE = true;
                //Disconnect();
            }

            return View();
        }

        #region button click events

        public ActionResult ConnectCore_Click()
        {
            if (Session["accessToken"] == null)
            {
                ViewBag.ShowConnect = true;
                ViewBag.ShowDisconnectCore = false;
                ViewBag.ShowLabelConnected = false;
                ViewBag.ShowSignInwithBQE = false;
                //call this once a day or at application_start in your code.
                discoverAuthData();

                //get JWKS keys
                getJWKSkeys();

                //doOauth for Connect to Quickbooks button
                authnticateMe("ConnectToCore");
            }
            else //if (Session["callMadeBy"].ToString() == "ConnectToCore")
            {
                //connect.Visible = false;
                //disconnectCore.Visible = true;
                //signInwithBQE.Visible = false;

                ViewBag.ShowConnect = false;
                ViewBag.ShowDisconnectCore = true;
                ViewBag.ShowSignInwithBQE = false;
                //Disconnect();
            }
            return View("Index");
            //return RedirectToAction("Index");

        }

        public ActionResult OpenId_Click()
        {
            if (Session["accessToken"] == null)
            {
                ViewBag.ShowConnect = true;
                ViewBag.ShowDisconnectCore = false;
                ViewBag.ShowLabelConnected = false;
                ViewBag.ShowSignInwithBQE = false;

                //call this once a day or at application_start in your code.
                discoverAuthData();

                //get JWKS keys
                getJWKSkeys();

                //doOauth for Get App Now button
                authnticateMe("OpenId");
            }
            else
            {
                //connect.Visible = false;
                //disconnectCore.Visible = true;
                //signInwithBQE.Visible = false;

                ViewBag.ShowConnect = false;
                ViewBag.ShowDisconnectCore = true;
                ViewBag.ShowSignInwithBQE = false;
                //Disconnect();
            }
            return View("Index");
            //return RedirectToAction("Index");

        }

        public ActionResult SIWC_Click()
        {
            if (Session["accessToken"] == null)
            {
                ViewBag.ShowConnect = true;
                ViewBag.ShowDisconnectCore = false;
                ViewBag.ShowLabelConnected = false;
                ViewBag.ShowSignInwithBQE = false;

                //call this once a day or at application_start in your code.
                discoverAuthData();

                //get JWKS keys
                getJWKSkeys();

                //doOauth for Sign In with BQE Software button
                authnticateMe("SIWC");
            }
            else
            {
                //connect.Visible = false;
                //disconnectCore.Visible = true;
                //signInwithBQE.Visible = false;

                ViewBag.ShowConnect = false;
                ViewBag.ShowDisconnectCore = true;
                ViewBag.ShowSignInwithBQE = false;
                //Disconnect();
            }
            return View("Index");
            //return RedirectToAction("Index");


        }

        public ActionResult Disconnect_Click()
        {
            if (Session["accessToken"] != null)// && Session["refreshToken"] != null)
            {
                //revoke tokens
                RevokeRefreshToken(Session["accessToken"].ToString(), Session["refreshToken"]?.ToString());
            }
            //Response.Redirect(Request.RawUrl.Replace(Request.Url.Query, ""));
            //return View("Index");
            //return RedirectToAction("Index");
            return RedirectToAction("Index");

        }

        public ActionResult CoreAPICall_Click()
        {
            //if (Session["companyId"] != null)  //TODO
            {
                if (Session["accessToken"] != null && Session["refreshToken"] != null)
                {
                    //call Core api
                    CoreApiCall(Session["accessToken"].ToString(), Session["refreshToken"].ToString(), Session["companyId"]?.ToString());
                }
            }
            /*else
            {
                LogMessage("SIWC call does not returns companyId for Core api call.");
                lblCoreCall.Visible = true;
                lblCoreCall.Text = "SIWC call does not returns companyId for Core api call";
            }*/
            return View("Index");
            //return RedirectToAction("Index");

        }

        public ActionResult CoreAPIPOST_Click()
        {
            //if (Session["companyId"] != null)  //TODO
            {
                if (Session["accessToken"] != null)// && Session["refreshToken"] != null)
                {
                    //call Core api
                    CoreApiPOSTAccount(Session["accessToken"].ToString(), Session["refreshToken"].ToString());
                }
            }
            /*else
            {
                LogMessage("SIWC call does not returns companyId for Core api call.");
                lblCoreCall.Visible = true;
                lblCoreCall.Text = "SIWC call does not returns companyId for Core api call";
            }*/
            //return View("Index");

            TempData["ShowCoreResponse"] = ViewBag.ShowCoreResponse;
            TempData["LabelCoreCall"] = ViewBag.LabelCoreCall;
            
            TempData.Keep("ShowLabelConnected");
            TempData.Keep("LabelCoreCall");

            return RedirectToAction("Index");

        }

        public ActionResult UserInfoAPICall_Click()
        {
            //if (Session["companyId"] != null)  //TODO
            {
                if (Session["accessToken"] != null)
                {
                    UserProfile userdata = fetchUserProfile(Session["accessToken"].ToString(), "");
                }
            }
            /*else
            {
                LogMessage("SIWC call does not returns companyId for Core api call.");
                lblCoreCall.Visible = true;
                lblCoreCall.Text = "SIWC call does not returns companyId for Core api call";
            }*/
            //return View("Index");
            //return RedirectToAction("Index");
            return RedirectToAction("Index");

        }

        #endregion

        #region Discovery data

        private void discoverAuthData()
        {
            LogMessage("Fetching Discovery Data.");

            DiscoveryData discoveryDataDecoded;

            // build the request    
            HttpWebRequest discoveryRequest = (HttpWebRequest)WebRequest.Create(discoveryURI);
            discoveryRequest.Method = "GET";
            discoveryRequest.Accept = "application/json";

            try
            {
                //call Discovery endpoint
                HttpWebResponse discoveryResponse = (HttpWebResponse)discoveryRequest.GetResponse();
                using (var discoveryDataReader = new StreamReader(discoveryResponse.GetResponseStream()))
                {
                    //read response
                    string responseText = discoveryDataReader.ReadToEnd();

                    // converts to dictionary
                    discoveryDataDecoded = JsonConvert.DeserializeObject<DiscoveryData>(responseText);

                }

                //Authorization endpoint url
                authorizationEndpoint = discoveryDataDecoded.Authorization_endpoint;

                //Token endpoint url
                tokenEndpoint = discoveryDataDecoded.Token_endpoint;

                //UseInfo endpoint url
                userinfoEndPoint = discoveryDataDecoded.Userinfo_endpoint;

                //Revoke endpoint url
                revokeEndpoint = discoveryDataDecoded.Revocation_endpoint;

                //Issuer endpoint Url 
                issuerUrl = discoveryDataDecoded.Issuer;

                //Json Web Key Store Url
                jwksEndpoint = discoveryDataDecoded.JWKS_uri;

                LogMessage("Discovery Data obtained.");
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {

                        LogMessage("HTTP Status: " + response.StatusCode);
                        var exceptionDetail = response.GetResponseHeader("WWW-Authenticate");
                        if (exceptionDetail != null && exceptionDetail != "")
                        {
                            LogMessage(exceptionDetail);
                        }
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // read response body
                            string responseText = reader.ReadToEnd();
                            if (responseText != null && responseText != "")
                            {
                                LogMessage(responseText);
                            }
                        }
                    }

                }
                else
                {
                    LogMessage(ex.Message);
                }
            }



        }

        #endregion


        #region OAuth2 calls
        public ActionResult authnticateMe(string callMadeBy)
        {
            LogMessage("Intiating OAuth2 call to get code.");
            string authorizationRequest = "";
            string scopeVal = "";

            //Generate the state and save this in DB to match it against the incoming_state value after this call is completed
            //Statecan be a unique Id, campaign id, tracking id or CSRF token
            string stateVal = randomDataBase64url(32);
            if (Session["CSRF"] == null)
            {
                Session["CSRF"] = stateVal;
            }

            //Decide scope based on which flow was initiated
            if (callMadeBy == "ConnectToCore") //ConnectToCore scopes
            {
                Session["callMadeBy"] = "ConnectToCore";
                scopeVal = scopeValConnectCore;

                //scopeVal = "readwrite:core";
                //authorizationEndpoint = "https://sandbox-api-identity.bqecore.com/idp/connect/authorize";
            }
            else if (callMadeBy == "OpenId")//Get App Now scopes
            {
                Session["callMadeBy"] = "OpenId";
                scopeVal = scopeValOpenId;
            }
            else if (callMadeBy == "SIWC")//Sign In With BQE Software scopes
            {
                Session["callMadeBy"] = "SIWC";
                scopeVal = scopeValSIWC;
            }

            if (!string.IsNullOrEmpty(authorizationEndpoint))
            {
                //Create the OAuth 2.0 authorization request.
                authorizationRequest = string.Format("{0}?client_id={1}&response_type=code&scope={2}&redirect_uri={3}&state={4}",
                    authorizationEndpoint, clientID, scopeVal, System.Uri.EscapeDataString(redirectURI), stateVal);

                if (callMadeBy == "ConnectToCore" || callMadeBy == "SIWC")
                {
                    //redirect to authorization request url
                    //PopUpWin(authorizationRequest, "_blank", "menubar=0,scrollbars=1,width=780,height=900,top=10");

                    ViewBag.OAuthURL = authorizationRequest;
                }
                else
                {
                    //redirect to authorization request url
                    Response.Redirect(authorizationRequest);
                }

            }
            else
            {
                LogMessage("Missing authorization Endpoint url!");
            }

            return View("Index");
        }

        public ActionResult exchangeCode(string code, string redirectURI, string companyId)
        {
            LogMessage("Exchanging code for tokens.");

            string id_token = "";
            string refresh_token = "";
            string access_token = "";
            bool isTokenValid = false;

            string cred = string.Format("{0}:{1}", clientID, Secret);
            string enc = Convert.ToBase64String(Encoding.ASCII.GetBytes(cred));
            string basicAuth = string.Format("{0} {1}", "Basic", enc);

            // build the  request            
            string accesstokenRequestBody = string.Format("grant_type=authorization_code&code={0}&redirect_uri={1}", code,
                System.Uri.EscapeDataString(redirectURI));

            // send the Token request
            HttpWebRequest accesstokenRequest = (HttpWebRequest)WebRequest.Create(tokenEndpoint);
            accesstokenRequest.Method = "POST";
            accesstokenRequest.ContentType = "application/x-www-form-urlencoded";
            accesstokenRequest.Accept = "application/json";
            accesstokenRequest.Headers[HttpRequestHeader.Authorization] = basicAuth;//Adding Authorization header

            byte[] _byteVersion = Encoding.ASCII.GetBytes(accesstokenRequestBody);
            accesstokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = accesstokenRequest.GetRequestStream();
            stream.Write(_byteVersion, 0, _byteVersion.Length);//verify
            stream.Close();

            try
            {
                // get the response
                HttpWebResponse accesstokenResponse = (HttpWebResponse)accesstokenRequest.GetResponse();
                using (var accesstokenReader = new StreamReader(accesstokenResponse.GetResponseStream()))
                {
                    //read response
                    string responseText = accesstokenReader.ReadToEnd();
                    //decode response
                    Dictionary<string, string> accesstokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

                    if (accesstokenEndpointDecoded.ContainsKey("id_token"))
                    {

                        id_token = accesstokenEndpointDecoded["id_token"];
                        access_token = accesstokenEndpointDecoded["access_token"];
                        Session["accessToken"] = access_token;

                        //validate idToken
                        isTokenValid = isIdTokenValid(id_token);
                        /*string idToken = id_token;
                        string[] splitValues = idToken.Split('.');
                        if (splitValues[0] != null)
                        {
                            //decode header 
                            var headerJson = Encoding.UTF8.GetString(FromBase64Url(splitValues[0].ToString()));
                            IdTokenHeader headerData = JsonConvert.DeserializeObject<IdTokenHeader>(headerJson);
                        }

                        if (splitValues[1] != null)
                        {
                            //decode payload
                            var payloadJson = Encoding.UTF8.GetString(FromBase64Url(splitValues[1].ToString()));
                            IdTokenPayload payloadData = JsonConvert.DeserializeObject<IdTokenPayload>(payloadJson);
                        }*/


                    }

                    if (accesstokenEndpointDecoded.ContainsKey("refresh_token"))
                    {
                        //save the refresh token in persistent store so that it can be used to refresh short lived access tokens
                        refresh_token = accesstokenEndpointDecoded["refresh_token"];
                        Session["refreshToken"] = refresh_token;


                        if (accesstokenEndpointDecoded.ContainsKey("access_token"))
                        {
                            LogMessage("Access token obtained.");
                            access_token = accesstokenEndpointDecoded["access_token"];
                            Session["accessToken"] = access_token;

                            //get userinfo
                            //This will work only for SIWC and Get App Now(OpenId) flows
                            //Since ConnectToCore flow does not has the required scopes, you will get exception.
                            //Here we will handle the exeception and then finally make Core api call
                            //In your code, based on your workflows/scope, you can choose to not make this call
                            UserProfile userdata = fetchUserProfile(access_token, refresh_token);

                        }
                    }


                    if (Session["callMadeby"].ToString() == "OpenId")
                    {
                        if (Request.Url.Query == "")
                        {
                            Response.Redirect(Request.RawUrl);
                        }
                        else
                        {
                            Response.Redirect(Request.RawUrl.Replace(Request.Url.Query, ""));
                        }
                    }
                    /*if (Session["callMadeby"].ToString() == "SIWC")//Sign In With BQE Software scopes
                    {
                        UserProfile userdata = fetchUserProfile(access_token, refresh_token);
                    }*/


                }

            }
            catch (WebException ex)
            {

                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {

                        LogMessage("HTTP Status: " + response.StatusCode);
                        var exceptionDetail = response.GetResponseHeader("WWW-Authenticate");
                        if (exceptionDetail != null && exceptionDetail != "")
                        {
                            LogMessage(exceptionDetail);
                        }
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // read response body
                            string responseText = reader.ReadToEnd();
                            if (responseText != null && responseText != "")
                            {
                                LogMessage(responseText);
                            }
                        }
                    }



                }
            }

            return View("Index");

        }


        private bool isIdTokenValid(string id_token)
        {
            LogMessage("Making IsIdTokenValid Call.");

            string idToken = id_token;
            string[] splitValues = idToken.Split('.');
            if (splitValues[0] != null)
            {

                //decode header 
                var headerJson = Encoding.UTF8.GetString(FromBase64Url(splitValues[0].ToString()));
                IdTokenHeader headerData = JsonConvert.DeserializeObject<IdTokenHeader>(headerJson);

                //Verify if the key id of the key used to sign the payload is not null
                if (headerData.Kid == null)
                {
                    return false;
                }

                //Verify if the hashing alg used to sign the payload is not null
                if (headerData.Alg == null)
                {
                    return false;
                }

            }
            if (splitValues[1] != null)
            {
                //decode payload
                var payloadJson = Encoding.UTF8.GetString(FromBase64Url(splitValues[1].ToString()));

                IdTokenPayload payloadData = JsonConvert.DeserializeObject<IdTokenPayload>(payloadJson);

                //verify aud matches clientId
                if (payloadData.Aud != null)
                {
                    if (payloadData.Aud.ToString() != clientID)  //if (payloadData.Aud[0].ToString() != clientID)
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }


                //verify authtime matches the time the ID token was authorized.                
                if (payloadData.Auth_time == null)
                {
                    return false;
                }



                //verify exp matches the time the ID token expires, represented in Unix time (integer seconds).                
                if (payloadData.Exp != null)
                {
                    ulong expiration = Convert.ToUInt64(payloadData.Exp);

                    TimeSpan epochTicks = new TimeSpan(new DateTime(1970, 1, 1).Ticks);
                    TimeSpan unixTicks = new TimeSpan(DateTime.UtcNow.Ticks) - epochTicks;
                    ulong unixTime = Convert.ToUInt64(unixTicks.Milliseconds);
                    //Verify the expiration time with what you expiry time have calculated and saved in your application
                    if ((expiration - unixTime) <= 0)
                    {

                        return false;
                    }
                }
                else
                {
                    return false;
                }


                //Verify iat matches the time the ID token was issued, represented in Unix time (integer seconds).            
                if (payloadData.Iat == null)
                {
                    return false;
                }


                //verify iss matches the  issuer identifier for the issuer of the response.     
                if (payloadData.Iss != null)
                {
                    if (payloadData.Iss.ToString() != issuerUrl)
                    {

                        return false;
                    }
                }
                else
                {
                    return false;
                }



                //verify sub. sub is an identifier for the user, unique among all BQE Software accounts and never reused. 
                //BQE Software account can have multiple emails at different points in time, but the sub value is never changed.
                //Use sub within your application as the unique-identifier key for the user.
                if (payloadData.Sub == null)
                {
                    return false;
                }


            }


            //verify Siganture matches the sigend concatenation of the encoded header and the encoded payload with the specified algorithm
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            //Read values of n and e from discovery document.
            rsa.ImportParameters(new RSAParameters()
            {
                //Read values from discovery document
                Modulus = FromBase64Url(mod),
                Exponent = FromBase64Url(expo)
            });

            //verify using RSA signature
            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(splitValues[0] + '.' + splitValues[1]));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            if (rsaDeformatter.VerifySignature(hash, FromBase64Url(splitValues[2])))
            {
                LogMessage("IdToken Signature is verified.");
                LogMessage("IsIdToken Valid Call completed.");
                return true;
            }
            else
            {
                LogMessage("Signature is compromised.");
                LogMessage("IsIdToken Valid Call completed.");
                return false;

            }

        }

        private void getJWKSkeys()
        {
            LogMessage("Making Get JWKS Keys Call.");

            JWKS jwksEndpointDecoded;

            // send the JWKS request
            HttpWebRequest jwksRequest = (HttpWebRequest)WebRequest.Create(jwksEndpoint);
            jwksRequest.Method = "GET";
            jwksRequest.Accept = "application/json";

            // get the response
            HttpWebResponse jwksResponse = (HttpWebResponse)jwksRequest.GetResponse();

            using (var jwksReader = new StreamReader(jwksResponse.GetResponseStream()))
            {
                //read response
                string responseText = jwksReader.ReadToEnd();

                //If the user already exists in your database, initiate an application session for that user.
                //If the user does not exist in your user database, redirect the user to your new- user, sign - up flow.
                //You may be able to auto - register the user based on the information you receive from BQE Software.
                //Or at the very least you may be able to pre - populate many of the fields that you require on your registration form.

                //Decode userInfo response
                jwksEndpointDecoded = JsonConvert.DeserializeObject<JWKS>(responseText);

            }

            //get mod and exponent value
            foreach (var key in jwksEndpointDecoded.Keys)
            {
                if (key.N != null)
                {
                    mod = key.N;
                }
                if (key.E != null)
                {
                    expo = key.E;
                }

            }

            LogMessage("JWKS Keys obtained.");

        }


        private void RefreshToken(string refresh_token)
        {
            LogMessage("Exchanging refresh token for access token.");//refresh token is valid for 100days and access token for 1hr
            string access_token = "";
            string cred = string.Format("{0}:{1}", clientID, Secret);
            string enc = Convert.ToBase64String(Encoding.ASCII.GetBytes(cred));
            string basicAuth = string.Format("{0} {1}", "Basic", enc);

            // build the  request
            string refreshtokenRequestBody = string.Format("grant_type=refresh_token&refresh_token={0}", refresh_token);

            // send the Refresh Token request
            HttpWebRequest refreshtokenRequest = (HttpWebRequest)WebRequest.Create(tokenEndpoint);
            refreshtokenRequest.Method = "POST";
            refreshtokenRequest.ContentType = "application/x-www-form-urlencoded";
            refreshtokenRequest.Accept = "application/json";
            //Adding Authorization header
            refreshtokenRequest.Headers[HttpRequestHeader.Authorization] = basicAuth;

            byte[] _byteVersion = Encoding.ASCII.GetBytes(refreshtokenRequestBody);
            refreshtokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = refreshtokenRequest.GetRequestStream();
            stream.Write(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            try
            {
                //get response
                HttpWebResponse refreshtokenResponse = (HttpWebResponse)refreshtokenRequest.GetResponse();
                using (var refreshTokenReader = new StreamReader(refreshtokenResponse.GetResponseStream()))
                {
                    //read response
                    string responseText = refreshTokenReader.ReadToEnd();

                    // decode response
                    Dictionary<string, string> refreshtokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

                    if (refreshtokenEndpointDecoded.ContainsKey("error"))
                    {
                        // Check for errors.
                        if (refreshtokenEndpointDecoded["error"] != null)
                        {
                            LogMessage(String.Format("OAuth token refresh error: {0}.", refreshtokenEndpointDecoded["error"]));
                            return;
                        }
                    }
                    else
                    {
                        //if no error
                        if (refreshtokenEndpointDecoded.ContainsKey("refresh_token"))
                        {

                            refresh_token = refreshtokenEndpointDecoded["refresh_token"];
                            Session["refreshToken"] = refresh_token;


                            if (refreshtokenEndpointDecoded.ContainsKey("access_token"))
                            {
                                //save both refresh token and new access token in permanent store
                                access_token = refreshtokenEndpointDecoded["access_token"];
                                Session["accessToken"] = access_token;



                            }
                        }
                    }



                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {

                        LogMessage("HTTP Status: " + response.StatusCode);
                        var exceptionDetail = response.GetResponseHeader("WWW-Authenticate");
                        if (exceptionDetail != null && exceptionDetail != "")
                        {
                            LogMessage(exceptionDetail);
                        }
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // read response body
                            string responseText = reader.ReadToEnd();
                            if (responseText != null && responseText != "")
                            {
                                LogMessage(responseText);
                            }
                        }
                    }

                }
            }

            LogMessage("Access token refreshed.");
        }

        private void RevokeRefreshToken(string access_token, string refresh_token)
        {
            LogMessage("Performing Revoke tokens.");

            string cred = string.Format("{0}:{1}", clientID, Secret);
            string enc = Convert.ToBase64String(Encoding.ASCII.GetBytes(cred));
            string basicAuth = string.Format("{0} {1}", "Basic", enc);

            // build the request
            string tokenRequestBody = "{\"token\":\"" + refresh_token + "\"}";

            // send the Revoke token request
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(revokeEndpoint);
            tokenRequest.Method = "POST";
            tokenRequest.ContentType = "application/json";
            tokenRequest.Accept = "application/json";
            //Add Authorization header
            tokenRequest.Headers[HttpRequestHeader.Authorization] = basicAuth;

            byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
            tokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = tokenRequest.GetRequestStream();
            stream.Write(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            try
            {
                //get the response
                HttpWebResponse response = (HttpWebResponse)tokenRequest.GetResponse();

                //here you should handle status code and take action based on that
                if (response.StatusCode == HttpStatusCode.OK)//200
                {
                    LogMessage("Successful Revoke!");
                    //disconnectCore.Visible = false;
                    //lblConnected.Visible = true;

                    ViewBag.ShowDisconnectCore = false;
                    ViewBag.ShowLabelConnected = true;

                }
                else if (response.StatusCode == HttpStatusCode.BadRequest)//400
                {
                    LogMessage("One or more of BearerToken, RefreshToken, ClientId or, Secret are incorrect.");
                }
                else if (response.StatusCode == HttpStatusCode.Unauthorized)//401
                {
                    LogMessage("Bad authorization header or no authorization header sent.");
                }
                else if (response.StatusCode == HttpStatusCode.InternalServerError)//500
                {
                    LogMessage("BQE Software server internal error, not the fault of the developer.");
                }

                //We are removing all sessions and qerystring here even if we get error on revoke. 
                //In your code, you can choose to handle the errors and then delete sessions and querystring
                Session.Clear();
                Session.Abandon();
                if (Request.Url.Query == "")
                {
                    Response.Redirect(Request.RawUrl);
                }
                else
                {
                    Response.Redirect(Request.RawUrl.Replace(Request.Url.Query, ""));
                }

            }
            catch (WebException ex)
            {
                Session.Clear();
                Session.Abandon();
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {

                        LogMessage("HTTP Status: " + response.StatusCode);
                        var exceptionDetail = response.GetResponseHeader("WWW-Authenticate");
                        if (exceptionDetail != null && exceptionDetail != "")
                        {
                            LogMessage(exceptionDetail);
                        }
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // read response body
                            string responseText = reader.ReadToEnd();
                            if (responseText != null && responseText != "")
                            {
                                LogMessage(responseText);
                            }
                        }
                    }

                }
            }

            LogMessage("Token revoked.");
        }

        private UserProfile fetchUserProfile(string access_token, string refresh_token)
        {
            LogMessage("Making Get User Profile Call.");

            // send the UserInfo endpoint request
            HttpWebRequest userinfoRequest = (HttpWebRequest)WebRequest.Create(userinfoEndPoint);
            userinfoRequest.Method = "GET";
            userinfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", access_token));
            userinfoRequest.Accept = "application/json";

            // get the response
            HttpWebResponse userinfoResponse = (HttpWebResponse)userinfoRequest.GetResponse();
            UserProfile userinfoEndpointDecoded;
            using (var userinfoReader = new StreamReader(userinfoResponse.GetResponseStream()))
            {
                //read response
                string responseText = userinfoReader.ReadToEnd();

                //If the user already exists in your database, initiate an application session for that user.
                //If the user does not exist in your user database, redirect the user to your new- user, sign - up flow.
                //You may be able to auto - register the user based on the information you receive from BQE Software.
                //Or at the very least you may be able to pre - populate many of the fields that you require on your registration form.

                //Decode userInfo response
                userinfoEndpointDecoded = JsonConvert.DeserializeObject<UserProfile>(responseText);

                string formattedModel = JsonConvert.SerializeObject(userinfoEndpointDecoded, Formatting.Indented);
                LogMessage("Communication with Core OK.");
                /*userInfoResponse.Visible = true;
                //lblUserInfo.Text = "Communication with Core OK";
                lblUserInfo.Text = formattedModel;
                lblUserInfo.Focus();*/

                ViewBag.ShowUserInfoResponse = true;
                ViewBag.LabelUserInfoText = formattedModel;


            }
            LogMessage("Get User Profile Call completed.");
            return userinfoEndpointDecoded;


        }

        #endregion


        #region Core calls

        private void CoreApiCall(string access_token, string refresh_token, string companyId)
        {
            try
            {
                //if (!string.IsNullOrEmpty(companyId)) //TODO
                {
                    LogMessage("Making Core API Call.");

                    string query = "";//"name=\"Accounts Payable\"";// "code=\"11000\"";
                    // build the  request
                    string encodedQuery = WebUtility.UrlEncode(query);

                    //add Corebase url and query
                    var uri = $"{coreBaseUrl}/api/account/query";

                    if (!string.IsNullOrEmpty(encodedQuery)) uri += "?where=" + encodedQuery;

                    // send the request
                    HttpWebRequest CoreApiRequest = (HttpWebRequest)WebRequest.Create(uri);
                    CoreApiRequest.Method = "GET";
                    CoreApiRequest.Headers.Add(string.Format("Authorization: Bearer {0}", access_token));
                    CoreApiRequest.ContentType = "application/json;charset=UTF-8";
                    CoreApiRequest.Accept = "*/*";


                    // get the response
                    HttpWebResponse CoreApiResponse = (HttpWebResponse)CoreApiRequest.GetResponse();
                    if (CoreApiResponse.StatusCode == HttpStatusCode.Unauthorized)//401
                    {
                        LogMessage("Invalid/Expired Access Token.");
                        //if you get a 401 token expiry then perform token refresh
                        RefreshToken(refresh_token);

                        //Retry Core API call again with new tokens
                        if (Session["accessToken"] != null && Session["refreshToken"] != null && Session["companyId"] != null)
                        {
                            CoreApiCall(Session["accessToken"].ToString(), Session["refreshToken"].ToString(), Session["companyId"]?.ToString());
                        }


                    }
                    else
                    {
                        //read Core api response
                        using (var CoreApiReader = new StreamReader(CoreApiResponse.GetResponseStream()))
                        {
                            string responseText = CoreApiReader.ReadToEnd();

                            dynamic parsedJson = JsonConvert.DeserializeObject(responseText);
                            string formattedModel = JsonConvert.SerializeObject(parsedJson, Formatting.Indented);

                            LogMessage("Communication with Core OK.");
                            /*coreResponse.Visible = true;
                            //lblCoreCall.Text = "Communication with Core OK";
                            lblCoreCall.Text = formattedModel;*/


                            ViewBag.ShowConnect = false;
                            ViewBag.ShowDisconnectCore = true;
                            ViewBag.ShowSignInwithBQE = false;

                            ViewBag.ShowCoreResponse = true;
                            ViewBag.LabelCoreCall = formattedModel;

                            //coreResponse.Focus();
                            //this.Page.SetFocus(coreResponse);
                            //Page page = (Page)HttpContext.Current.Handler;
                            //page.SetFocus(lblCoreCall);

                            //Page.ClientScript.RegisterStartupScript(this.GetType(), "focusthis", "document.getElementById('" + lblCoreCall + "').focus()", true);

                        }

                    }

                }

            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {

                        LogMessage("HTTP Status: " + response.StatusCode);
                        var exceptionDetail = response.GetResponseHeader("WWW-Authenticate");
                        if (exceptionDetail != null && exceptionDetail != "")
                        {
                            LogMessage(exceptionDetail);
                        }
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // read response body
                            string responseText = reader.ReadToEnd();
                            if (responseText != null && responseText != "")
                            {
                                LogMessage(responseText);
                            }
                        }
                    }

                }
            }
        }

        private void CoreApiPOSTAccount(string access_token, string refresh_token)
        {
            LogMessage("Performing POST data.");

            var randomizer = new Random();
            var nextValue = randomizer.Next(100, 99999);

            // build the object
            string requestBody = "{\"code\":\"" + nextValue + "\",\"type\":1,\"name\":\"Test Account" + nextValue +"\",\"displayAccount\":\"10000 - Test Account\",\"description\":\"Accounts Test\",\"level\":0,\"rootAccountId\":null," +
                "\"isActive\":true,\"parentAccountId\":null,\"parentAccount\":null,\"openingBalance\":0.00000000,\"openingBalanceAsOf\":null,\"routingNumber\":null,\"runningBalance\":118737.5800}";

            //add Corebase url and query
            var uri = $"{coreBaseUrl}/api/account";

            // send the post request
            HttpWebRequest CoreApiRequest = (HttpWebRequest)WebRequest.Create(uri);
            CoreApiRequest.Method = "POST";
            CoreApiRequest.ContentType = "application/json";
            CoreApiRequest.Accept = "*/*";
            CoreApiRequest.Headers.Add(string.Format("Authorization: Bearer {0}", access_token));

            byte[] _byteVersion = Encoding.ASCII.GetBytes(requestBody);
            CoreApiRequest.ContentLength = _byteVersion.Length;
            Stream stream = CoreApiRequest.GetRequestStream();
            stream.Write(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            try
            {
                //get the response
                HttpWebResponse response = (HttpWebResponse)CoreApiRequest.GetResponse();

                //here you should handle status code and take action based on that
                if (response.StatusCode == HttpStatusCode.Unauthorized)//401
                {
                    LogMessage("Invalid/Expired Access Token.");
                    //if you get a 401 token expiry then perform token refresh
                    RefreshToken(refresh_token);

                    //Retry Core API call again with new tokens
                    if (Session["accessToken"] != null)
                    {
                        CoreApiPOSTAccount(Session["accessToken"].ToString(), Session["refreshToken"].ToString());
                    }

                }
                else if (response.StatusCode == HttpStatusCode.Created)//201
                {
                    LogMessage("Successful POST!");

                    //read Core api response
                    using (var CoreApiReader = new StreamReader(response.GetResponseStream()))
                    {
                        string responseText = CoreApiReader.ReadToEnd();

                        dynamic parsedJson = JsonConvert.DeserializeObject(responseText);
                        string formattedModel = JsonConvert.SerializeObject(parsedJson, Formatting.Indented);

                        /*LogMessage("Communication with Core OK.");
                        coreResponse.Visible = true;
                        //lblCoreCall.Text = "Communication with Core OK";
                        lblCoreCall.Text = formattedModel;
                        lblCoreCall.Focus();*/

                        ViewBag.ShowConnect = false;
                        ViewBag.ShowDisconnectCore = true;
                        ViewBag.ShowSignInwithBQE = false;

                        ViewBag.ShowCoreResponse = true;
                        ViewBag.LabelCoreCall = formattedModel;

                    }
                }

            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {

                        LogMessage("HTTP Status: " + response.StatusCode);
                        var exceptionDetail = response.GetResponseHeader("WWW-Authenticate");
                        if (exceptionDetail != null && exceptionDetail != "")
                        {
                            LogMessage(exceptionDetail);
                        }
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // read response body
                            string responseText = reader.ReadToEnd();
                            if (responseText != null && responseText != "")
                            {
                                LogMessage(responseText);
                            }
                        }
                    }

                }
            }

            LogMessage("New Record Added.");
        }

        #endregion

        #region 0auth2 methods

        public void PopUpWin(string url, string target, string windowFeatures)
        {

            if ((String.IsNullOrEmpty(target) || target.Equals("_self", StringComparison.OrdinalIgnoreCase)) && String.IsNullOrEmpty(windowFeatures))
            {
                Response.Redirect(url);
            }
            else
            {
                Page page = null;// (Page)HttpContext.Current.Handler;

                if (page == null)
                {
                    throw new InvalidOperationException("Cannot redirect to new window outside Page context.");
                }
                url = page.ResolveClientUrl(url);

                string script;
                if (!String.IsNullOrEmpty(windowFeatures))
                {
                    script = @"window.open(""{0}"", ""{1}"", ""{2}"");";
                }
                else
                {
                    script = @"window.open(""{0}"", ""{1}"");";
                }
                script = String.Format(script, url, target, windowFeatures);
                ScriptManager.RegisterStartupScript(page, typeof(Page), "Redirect", script, true);
            }
        }

        /// <summary>
        /// Returns URI-safe data with a given input length.
        /// </summary>
        /// <param name="length">Input length (nb. output will be longer)</param>
        /// <returns></returns>
        public static string randomDataBase64url(uint length)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return base64urlencodeNoPadding(bytes);
        }

        /// <summary>
        /// Base64url no-padding encodes the given input buffer. (encode)
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static string base64urlencodeNoPadding(byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }

        /// <summary>
        /// Returns the SHA256 hash of the input string.
        /// </summary>
        /// <param name="inputStirng"></param>
        /// <returns></returns>
        public static byte[] sha256(string inputString)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(inputString);
            SHA256Managed sha256 = new SHA256Managed();
            return sha256.ComputeHash(bytes);
        }

        /// <summary>
        /// Generates byte array  from Base64url string (decode)
        /// </summary>
        /// <param name="base64Url"></param>
        /// <returns></returns>
        static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                                  .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

        /// <summary>
        /// Appends the given string to the on-screen log, and the debug console.
        /// </summary>
        /// <param name="output">string to be appended</param>
        public string GetLogPath()
        {
            try
            {
                if (logPath == "")
                {
                    logPath = System.Environment.GetEnvironmentVariable("TEMP");
                    if (!logPath.EndsWith("\\")) logPath += "\\";
                }
            }
            catch
            {
                LogMessage("Log error path not found.");
            }

            return logPath;

        }


        /// <summary>
        /// Appends the given string to the on-screen log, and the debug console.
        /// </summary>
        /// <param name="output">string to be appended</param>
        public void LogMessage(string logMsg)
        {
            try
            {
                //Console.WriteLine(logMsg);
                System.IO.StreamWriter sw = System.IO.File.AppendText(GetLogPath() + "CoreAppLogs.txt");
                try
                {
                    string logLine = System.String.Format("{0:G}: {1}.", System.DateTime.Now, logMsg);
                    sw.WriteLine(logLine);
                }
                finally
                {
                    sw.Close();
                }
            }
            catch(Exception ex)
            {

            }
            
        }


        #endregion

        
    }
}