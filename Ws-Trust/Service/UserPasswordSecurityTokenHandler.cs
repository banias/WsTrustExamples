using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Claim = System.IdentityModel.Claims.Claim;

namespace Ws_Trust.Service
{
    public class UserPasswordSecurityTokenHandler : UserNameSecurityTokenHandler
    {
        public override bool CanValidateToken { get { return true; } }

        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {
            var userToken = token as UserNameSecurityToken;

            if (userToken == null)
                throw new ArgumentNullException("token");

            if (userToken.UserName == "admin" && userToken.Password == "passwd")
                return new[]
                {
                    new ClaimsIdentity(new[]
                    {new System.Security.Claims.Claim(ClaimTypes.NameIdentifier, userToken.UserName),})
                }.ToList().AsReadOnly();

            return new List<ClaimsIdentity>().AsReadOnly();
        }

        public override Type TokenType
        {
            get
            {
                return typeof(UserNameSecurityToken);
            }
        }
    }
}
