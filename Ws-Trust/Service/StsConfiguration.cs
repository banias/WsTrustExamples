using System;
using System.Collections.Generic;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;

namespace Ws_Trust.Service
{
    public class StsConfiguration : SecurityTokenServiceConfiguration
    {
        public StsConfiguration()
        {
            TokenIssuerName = "CustomSts";
           
            SecurityTokenService = typeof (StsService);
            ServiceCertificate = StsHelper.GetCertificate();    

            SecurityTokenHandlers.Remove(SecurityTokenHandlers.OfType<WindowsUserNameSecurityTokenHandler>().Single());
            SecurityTokenHandlers.AddOrReplace(new UserPasswordSecurityTokenHandler());
        }
    }
}
