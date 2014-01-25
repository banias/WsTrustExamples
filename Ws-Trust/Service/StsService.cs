using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Ws_Trust.Service
{
    public class StsService : SecurityTokenService
    {
        public StsService(SecurityTokenServiceConfiguration securityTokenServiceConfiguration) : base(securityTokenServiceConfiguration)
        {
        }

        protected override Scope GetScope(ClaimsPrincipal principal, RequestSecurityToken request)
        {
            var result = new Scope(request.AppliesTo.Uri.ToString(), new X509SigningCredentials(StsHelper.GetCertificate()), new X509EncryptingCredentials(StsHelper.GetCertificate()));
            return result;
        }

        protected override ClaimsIdentity GetOutputClaimsIdentity(ClaimsPrincipal principal, RequestSecurityToken request, Scope scope)
        {
            return
                new ClaimsIdentity(new[]
                {new Claim(ClaimTypes.NameIdentifier, "someUser"), new Claim(ClaimTypes.Email, "some@email.com"),});
        }
    }
}
