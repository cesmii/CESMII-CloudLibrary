/* ========================================================================
 * Copyright (c) 2005-2021 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

namespace Opc.Ua.Cloud.Library
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http.Headers;
    using System.Security.Claims;
    using System.Text;
    using System.Text.Encodings.Web;
    using System.Threading.Tasks;
    using HotChocolate.Execution;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Microsoft.Extensions.Primitives;
    using Opc.Ua.Cloud.Library.Interfaces;

    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IUserService _userService;
        private readonly SignInManager<IdentityUser> _signInManager;
        //private readonly AuthenticationProperties _props = null;
        //private readonly UserManager<IdentityUser> _userManager = null;
        //private readonly string _azureKey = "498e71d6-2d30-4e77-bdca-ee84ebd04125";
        public BasicAuthenticationHandler(
            IUserService userService,
            //UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
            _userService = userService;
            _signInManager = signInManager;
            //_props = _signInManager.ConfigureExternalAuthenticationProperties("AzureAdProvider", "https://login.microsoftonline.com/");
            //_userManager = userManager;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string username = null;
            IEnumerable<Claim> claims = null;
            try
            {
                if (StringValues.IsNullOrEmpty(Request.Headers["Authorization"]))
                {

                    if (_signInManager.IsSignedIn(Request.HttpContext.User) || Request.HttpContext.User.Identity != null)
                    {
                        // Allow a previously authenticated, signed in user (for example via ASP.Net cookies from the graphiql browser)
                        ClaimsPrincipal principal2 = new ClaimsPrincipal(Request.HttpContext.User.Identity);
                        AuthenticationTicket ticket2 = new AuthenticationTicket(principal2, Scheme.Name);


                        //var user = await _userManager.FindByNameAsync(principal2.Identity.Name);
                        //if (user == null)
                        //{
                        //    var newUser = new IdentityUser {
                        //        UserName = principal2.Identity.Name,
                        //    };
                        //    var result = await _userManager.CreateAsync(newUser);
                        //    user = await _userManager.FindByNameAsync(principal2.Identity.Name);
                        //}
                        ////var x = await _signInManager.ExternalLoginSignInAsync("AzureAdProvider", _azureKey, false);
                        //await _signInManager.SignInWithClaimsAsync(user, _props, Request.HttpContext.User.Claims);

                        return AuthenticateResult.Success(ticket2);
                    }
                    throw new ArgumentException("Authentication header missing in request!");
                }

                AuthenticationHeaderValue authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
                string[] credentials = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Parameter)).Split(':');
                username = credentials.FirstOrDefault();
                string password = credentials.LastOrDefault();

                claims = await _userService.ValidateCredentialsAsync(username, password).ConfigureAwait(false);
                if (claims?.Any() != true)
                {
                    throw new ArgumentException("Invalid credentials");
                }
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail($"Authentication failed: {ex.Message}");
            }
            if (claims == null)
            {
                throw new ArgumentException("Invalid credentials");
            }
            ClaimsIdentity identity = new ClaimsIdentity(claims, Scheme.Name);
            ClaimsPrincipal principal = new ClaimsPrincipal(identity);
            AuthenticationTicket ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
    }
}
