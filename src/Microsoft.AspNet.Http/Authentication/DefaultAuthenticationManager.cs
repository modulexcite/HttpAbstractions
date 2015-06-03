// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.FeatureModel;
using Microsoft.AspNet.Http.Features;
using Microsoft.AspNet.Http.Features.Authentication;
using Microsoft.AspNet.Http.Features.Authentication.Internal;
using Microsoft.Framework.Internal;

namespace Microsoft.AspNet.Http.Authentication.Internal
{
    public class DefaultAuthenticationManager : AuthenticationManager
    {
        private readonly IFeatureCollection _features;
        private FeatureReference<IHttpAuthenticationFeature> _authentication = FeatureReference<IHttpAuthenticationFeature>.Default;
        private FeatureReference<IHttpResponseFeature> _response = FeatureReference<IHttpResponseFeature>.Default;

        public DefaultAuthenticationManager(IFeatureCollection features)
        {
            _features = features;
        }

        private IHttpAuthenticationFeature HttpAuthenticationFeature
        {
            get { return _authentication.Fetch(_features) ?? _authentication.Update(_features, new HttpAuthenticationFeature()); }
        }

        private IHttpResponseFeature HttpResponseFeature
        {
            get { return _response.Fetch(_features); }
        }

        public override IEnumerable<AuthenticationDescription> GetAuthenticationSchemes()
        {
            var handler = HttpAuthenticationFeature.Handler;
            if (handler == null)
            {
                return new AuthenticationDescription[0];
            }

            var describeContext = new DescribeSchemesContext();
            handler.GetDescriptions(describeContext);
            return describeContext.Results.Select(description => new AuthenticationDescription(description));
        }

        public override void Authenticate([NotNull] AuthenticateContext context)
        {
            var handler = HttpAuthenticationFeature.Handler;

            if (handler != null)
            {
                handler.Authenticate(context);
            }

            if (!context.Accepted)
            {
                throw new InvalidOperationException($"The following authentication scheme was not accepted: {context.AuthenticationScheme}");
            }
        }

        public override async Task AuthenticateAsync([NotNull] AuthenticateContext context)
        {
            var handler = HttpAuthenticationFeature.Handler;

            if (handler != null)
            {
                await handler.AuthenticateAsync(context);
            }

            if (!context.Accepted)
            {
                throw new InvalidOperationException($"The following authentication scheme was not accepted: {context.AuthenticationScheme}");
            }
        }

        private void ChallengeInternal(string authenticationScheme, AuthenticationProperties properties, ChallengeBehavior behavior)
        {
            var handler = HttpAuthenticationFeature.Handler;

            var challengeContext = new ChallengeContext(authenticationScheme, properties?.Items, behavior);
            if (handler != null)
            {
                handler.Challenge(challengeContext);
            }

            // The default Challenge with no scheme is always accepted
            if (!challengeContext.Accepted && !string.IsNullOrEmpty(authenticationScheme))
            {
                throw new InvalidOperationException($"The following authentication scheme was not accepted: {authenticationScheme}");
            }
        }

        // You are not allowed access
        public void Forbidden(string authenticationScheme, AuthenticationProperties properties)
        {
            ChallengeInternal(authenticationScheme, properties, ChallengeBehavior.Forbidden);
        }

        // Sometimes send to login, sometimes not allowed, up to middleware (do the right thing)
        public override void Challenge(string authenticationScheme, AuthenticationProperties properties)
        {
            ChallengeInternal(authenticationScheme, properties, ChallengeBehavior.Automatic);
        }

        public override void SignIn([NotNull] string authenticationScheme, [NotNull] ClaimsPrincipal principal, AuthenticationProperties properties)
        {
            var handler = HttpAuthenticationFeature.Handler;

            var signInContext = new SignInContext(authenticationScheme, principal, properties?.Items);
            if (handler != null)
            {
                handler.SignIn(signInContext);
            }

            if (!signInContext.Accepted)
            {
                throw new InvalidOperationException($"The following authentication scheme was not accepted: {authenticationScheme}");
            }
        }

        public override void SignOut(string authenticationScheme, AuthenticationProperties properties)
        {
            var handler = HttpAuthenticationFeature.Handler;

            var signOutContext = new SignOutContext(authenticationScheme, properties?.Items);
            if (handler != null)
            {
                handler.SignOut(signOutContext);
            }

            if (!string.IsNullOrWhiteSpace(authenticationScheme) && !signOutContext.Accepted)
            {
                throw new InvalidOperationException($"The following authentication scheme was not accepted: {authenticationScheme}");
            }
        }

        public override void SignOut(string authenticationScheme)
        {
            SignOut(authenticationScheme, properties: null);
        }
    }
}
