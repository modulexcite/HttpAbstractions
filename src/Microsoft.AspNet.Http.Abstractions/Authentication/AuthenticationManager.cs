// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNet.Http.Features.Authentication;

namespace Microsoft.AspNet.Http.Authentication
{
    public abstract class AuthenticationManager
    {
        public abstract IEnumerable<AuthenticationDescription> GetAuthenticationSchemes();

        public void Authenticate(AuthenticateContext context)
        {
            AuthenticateAsync(context).GetAwaiter().GetResult();
        }

        public abstract Task AuthenticateAsync(AuthenticateContext context);

        public ClaimsPrincipal Authenticate(string authenticationScheme)
        {
            var context = new AuthenticateContext(authenticationScheme);
            Authenticate(context);
            return context.Principal;
        }

        public async Task<ClaimsPrincipal> AuthenticateAsync(string authenticationScheme)
        {
            var context = new AuthenticateContext(authenticationScheme);
            await AuthenticateAsync(context);
            return context.Principal;
        }

        public virtual Task ChallengeAsync()
        {
            return ChallengeAsync(authenticationScheme: null, properties: null);
        }

        public virtual Task ChallengeAsync(AuthenticationProperties properties)
        {
            return ChallengeAsync(authenticationScheme: null, properties: properties);
        }

        public virtual Task ChallengeAsync(string authenticationScheme)
        {
            return ChallengeAsync(authenticationScheme: authenticationScheme, properties: null);
        }

        // Leave it up to authentication handler to do the right thing for the challenge
        public Task ChallengeAsync(string authenticationScheme, AuthenticationProperties properties)
        {
            return ChallengeAsync(authenticationScheme, properties, ChallengeBehavior.Automatic);
        }

        public Task SignInAsync(string authenticationScheme, ClaimsPrincipal principal)
        {
            return SignInAsync(authenticationScheme, principal, properties: null);
        }

        public Task ForbidAsync(string authenticationScheme)
        {
            return ForbidAsync(authenticationScheme, properties: null);
        }

        // Deny access (typically a 403)
        public Task ForbidAsync(string authenticationScheme, AuthenticationProperties properties)
        {
            return ChallengeAsync(authenticationScheme, properties, ChallengeBehavior.Forbidden);
        }

        public abstract Task ChallengeAsync(string authenticationScheme, AuthenticationProperties properties, ChallengeBehavior behavior);

        public abstract Task SignInAsync(string authenticationScheme, ClaimsPrincipal principal, AuthenticationProperties properties);

        public Task SignOutAsync()
        {
            return SignOutAsync(authenticationScheme: null, properties: null);
        }

        public Task SignOutAsync(string authenticationScheme)
        {
            return SignOutAsync(authenticationScheme, properties: null);
        }

        public abstract Task SignOutAsync(string authenticationScheme, AuthenticationProperties properties);
    }
}
