using System;
using System.Linq;
using System.Security.Claims;
using Owin;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Extensions;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Owin;
using Sustainsys.Saml2.Metadata;
using Microsoft.Owin.Infrastructure;
using Sitecore.Abstractions;

namespace YourProjectName
{
     
    public class MySaml2Authentication : IdentityProvidersProcessor
    {       
        public MySaml2Authentication(
                FederatedAuthenticationConfiguration federatedAuthenticationConfiguration,
                ICookieManager cookieManager,
                BaseSettings settings) :
            base(federatedAuthenticationConfiguration, cookieManager, settings)
        {

        }

		/// <summary>
        /// Identity Providr name, This has to match the configuration yu mentioned in config.
		/// You can change as per your naming standards.
        /// </summary>
        protected override string IdentityProviderName
        {
            get { return "saml2"; }
        }
		
        protected override void ProcessCore(IdentityProvidersArgs args)
        {  
		    Assert.ArgumentNotNull(args, "args");
            //Settings from config
            string entityId = Settings.GetSetting("MyProject.EntityId");
            string returnUrl = Settings.GetSetting("MyProject.ReturnUrl");          
            string metadataLocation = Settings.GetSetting("MyProject.MetadataLocation");

            var options = new Saml2AuthenticationOptions(false)
            {
                SPOptions = new SPOptions
                {
                    EntityId = new System.IdentityModel.Metadata.EntityId(entityId),
                    ReturnUrl = new Uri(returnUrl)
                },
                AuthenticationType = GetAuthenticationType()
            };

            options.IdentityProviders.Add(
			new Sustainsys.Saml2.IdentityProvider(new System.IdentityModel.Metadata.EntityId(entityId), options.SPOptions)
            {
                MetadataLocation = metadataLocation,
                LoadMetadata = true
            });

            options.Notifications = new Saml2Notifications
            {
                AcsCommandResultCreated = (result, response) =>
                {
                    var identityProvider = GetIdentityProvider();
                    ((ClaimsIdentity)result.Principal.Identity).ApplyClaimsTransformations(
					new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                }
            };
           
            args.App.UseSaml2Authentication(options);
        }
    }
}