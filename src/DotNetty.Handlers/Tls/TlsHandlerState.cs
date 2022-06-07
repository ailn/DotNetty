// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Handlers.Tls
{
    using System;

    [Flags]
    enum TlsHandlerState
    {
        Authenticating = 1,
        Authenticated = 1 << 1,
        FailedAuthentication = 1 << 2,
        ReadRequestedBeforeAuthenticated = 1 << 3,
        FlushedBeforeHandshake = 1 << 4,
        AuthenticationStarted = Authenticating | Authenticated | FailedAuthentication,
        AuthenticationCompleted = Authenticated | FailedAuthentication
    }
}