// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Handlers.Tls;

using System;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

partial class TlsHandler
{
    static readonly Action<Task, object> HandshakeCompletionCallback = new Action<Task, object>(HandleHandshakeCompleted);
    Stopwatch sw;

    bool EnsureAuthenticated()
    {
        Trace(nameof(TlsHandler), $"{nameof(this.EnsureAuthenticated)} state: {this.state}");

        lock (this.sync)
        {
            TlsHandlerState oldState = this.state;
            if (oldState.HasAny(TlsHandlerState.AuthenticationStarted))
            {
                return oldState.HasAny(TlsHandlerState.Authenticated);
            }

            Trace(nameof(TlsHandler), "!oldState.HasAny(TlsHandlerState.AuthenticationStarted)");
            this.state = oldState | TlsHandlerState.Authenticating;
        }

        if (this.IsServer)
        {
            var serverSettings = (ServerTlsSettings)this.settings;
            Trace(nameof(TlsHandler), $"{nameof(this.EnsureAuthenticated)} AuthenticateAsServerAsync");
            this.sw = Stopwatch.StartNew();
            this.sslStream.AuthenticateAsServerAsync(
                    serverSettings.Certificate,
                    serverSettings.NegotiateClientCertificate,
                    serverSettings.EnabledProtocols,
                    serverSettings.CheckCertificateRevocation)
                .ContinueWith(HandshakeCompletionCallback, this, TaskContinuationOptions.ExecuteSynchronously);
        }
        else
        {
            var clientSettings = (ClientTlsSettings)this.settings;
            Trace(nameof(TlsHandler), $"{nameof(this.EnsureAuthenticated)} AuthenticateAsClientAsync");
            this.sw = Stopwatch.StartNew();
            this.sslStream.AuthenticateAsClientAsync(
                    clientSettings.TargetHost,
                    clientSettings.X509CertificateCollection,
                    clientSettings.EnabledProtocols,
                    clientSettings.CheckCertificateRevocation)
                .ContinueWith(HandshakeCompletionCallback, this, TaskContinuationOptions.ExecuteSynchronously);
        }

        return false;
    }

    void NotifyHandshakeFailure(Exception cause)
    {
        lock (this.sync)
        {
            if (this.state.HasAny(TlsHandlerState.AuthenticationCompleted))
            {
                Trace(nameof(TlsHandler), nameof(this.NotifyHandshakeFailure) + " AuthenticationCompleted");
                return;
            }
            
            Trace(nameof(TlsHandler), nameof(this.NotifyHandshakeFailure));
            // handshake was not completed yet => TlsHandler react to failure by closing the channel
            this.state = (this.state | TlsHandlerState.FailedAuthentication) & ~TlsHandlerState.Authenticating;
        }
        
        this.capturedContext.FireUserEventTriggered(new TlsHandshakeCompletionEvent(cause));
        this.CloseAsync(this.capturedContext);
    }

    static void HandleHandshakeCompleted(Task task, TlsHandler self)
    {
        Trace(nameof(TlsHandler), $"{nameof(HandleHandshakeCompleted)}, state: {self.state}, task.Status: {task.Status}, elapsed: {self.sw.Elapsed}");

        lock (self.sync)
        {
            switch (task.Status)
            {
                case TaskStatus.RanToCompletion:
                {
                    TlsHandlerState oldState = self.state;

                    Contract.Assert(!oldState.HasAny(TlsHandlerState.AuthenticationCompleted));
                    self.state = (oldState | TlsHandlerState.Authenticated) & ~(TlsHandlerState.Authenticating | TlsHandlerState.FlushedBeforeHandshake);

                    self.capturedContext.FireUserEventTriggered(TlsHandshakeCompletionEvent.Success);

                    if (oldState.Has(TlsHandlerState.ReadRequestedBeforeAuthenticated) && !self.capturedContext.Channel.Configuration.AutoRead)
                    {
                        Trace(nameof(TlsHandler), $"{nameof(HandleHandshakeCompleted)}, self.capturedContext.Read();");
                        self.capturedContext.Read();
                    }

                    if (oldState.Has(TlsHandlerState.FlushedBeforeHandshake))
                    {
                        Trace(nameof(TlsHandler), $"{nameof(HandleHandshakeCompleted)}, self.Wrap(self.capturedContext); self.capturedContext.Flush();");
                        self.Wrap(self.capturedContext);
                        self.capturedContext.Flush();
                    }

                    break;
                }
                case TaskStatus.Canceled:
                case TaskStatus.Faulted:
                {
                    // ReSharper disable once AssignNullToNotNullAttribute -- task.Exception will be present as task is faulted
                    TlsHandlerState oldState = self.state;
                    Contract.Assert(!oldState.HasAny(TlsHandlerState.Authenticated));
                    self.HandleFailure(task.Exception);
                    break;
                }
                default:
                    throw new ArgumentOutOfRangeException(nameof(task), "Unexpected task status: " + task.Status);
            }
        }
    }

    static void HandleHandshakeCompleted(Task task, object state)
    {
        var self = (TlsHandler)state;

        if (self.capturedContext.Executor.InEventLoop)
        {
            HandleHandshakeCompleted(task, self);
        }
        else
        {
            self.capturedContext.Executor.Execute(() => HandleHandshakeCompleted(task, self));
        }
    }
}