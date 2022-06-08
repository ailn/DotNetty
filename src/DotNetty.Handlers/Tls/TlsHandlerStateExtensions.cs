// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Handlers.Tls
{
    static class TlsHandlerStateExtensions
    {
        public static bool Has(this TlsHandlerState value, TlsHandlerState testValue) => (value & testValue) == testValue;

        public static bool HasAny(this TlsHandlerState value, TlsHandlerState testValue) => (value & testValue) != 0;
    }
}