using Microsoft.Owin.Infrastructure;
using Sitecore.Abstractions;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using System.Web;
using Owin.Security.Providers.PingFederate;
using Owin.Security.Providers.PingFederate.Provider;
using System.Security.Claims;
using Sitecore.Owin.Authentication.Services;
using Microsoft.Owin;
using System.Web.Mvc;
using Newtonsoft.Json.Linq;

namespace YourProjectName
{
    public class MyAuthentication : IdentityProvidersProcessor
    {
        public MyAuthentication(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration,
            ICookieManager cookieManager, BaseSettings settings) :
            base(federatedAuthenticationConfiguration, cookieManager, settings)
		{				
		}
			
        /// <summary>
        /// Identity Providr name, This has to match the configuration yu mentioned in config.
		/// You can change as per your naming standards.
        /// </summary>
        protected override string IdentityProviderName
        {
            get { return "PingFederate"; }
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider identityProvider = this.GetIdentityProvider();
            string authenticationType = this.GetAuthenticationType();
			
			//Settings from config
            string clientId = Settings.GetSetting("MyProject.ClientId");
            string clientSecret = Settings.GetSetting("MyProject.ClientSecret");
            string pingFederateUrl = Settings.GetSetting("MyProject.PingFederateUrl");
            string callbackPath = Settings.GetSetting("MyProject.CallbackPath");

            var provider = new PingFederateAuthenticationProvider()
            {

                OnAuthenticated = (context) =>
                {
                    //Log token, only if need to check all available values inside it else comment out this line.
                    Sitecore.Diagnostics.Log.Info(context.Identity.Claims.FirstOrDefault(x => x.Type == "id_token").Value, this);
					
                    //Add additional claims for property mapping as this library has limited mappings covered inside
                    context.Identity.AddClaim(new Claim("uid", context.User.Value<string>("uid")));
                    context.Identity.AddClaim(new Claim("mail", context.User.Value<string>("mail")));
                    context.Identity.AddClaim(new Claim("displayName", context.User.Value<string>("displayName")));	

                    //Add additional claims for groups/memberOf mapping as this library has limited mappings covered inside
                    if (context.User.Value<JArray>("memberOf") != null)	
                    {
                        foreach (var groups in context.User.Value<JArray>("memberOf"))
                        {
                            context.Identity.AddClaim(new Claim("memberOf", GetMemberGroup(groups.Value<string>())));
                        }
                    }
	
                    //Transform all mappings
                    ClaimsIdentity identity = context.Identity;	

                    foreach (Transformation current in identityProvider.Transformations)
                    {
                        current.Transform(identity, new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                    }
                    return System.Threading.Tasks.Task.FromResult(0);
                }                
            };

            var options = new PingFederateAuthenticationOptions();
            options.AuthenticationType = GetAuthenticationType();
            options.ClientId = clientId;
            options.ClientSecret = clientSecret;
            options.Provider = provider;
            options.PingFederateUrl = pingFederateUrl;
            options.CallbackPath = new PathString(callbackPath);
            args.App.UsePingFederateAuthentication(options);
        }
    }
}