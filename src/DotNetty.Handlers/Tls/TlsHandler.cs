// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Handlers.Tls
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Diagnostics.Contracts;
    using System.IO;
    using System.Net.Security;
    using System.Runtime.ExceptionServices;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;
    using DotNetty.Buffers;
    using DotNetty.Codecs;
    using DotNetty.Common.Concurrency;
    using TaskCompletionSource = DotNetty.Common.Concurrency.TaskCompletionSource;
    using DotNetty.Common.Utilities;
    using DotNetty.Transport.Channels;

    public sealed partial class TlsHandler : ByteToMessageDecoder
    {
        readonly TlsSettings settings;
        const int FallbackReadBufferSize = 256;
        const int UnencryptedWriteBatchSize = 14 * 1024;

        static readonly Exception ChannelClosedException = new IOException("Channel is closed");

        readonly SslStream sslStream;
        readonly MediationStream mediationStream;
        readonly TaskCompletionSource closeFuture;

        TlsHandlerState state;
        volatile IChannelHandlerContext capturedContext;
        IByteBuffer pendingSslStreamReadBuffer;
        Task<int> pendingSslStreamReadFuture;
        readonly object sync = new object();

        public static readonly ConcurrentQueue<string> Events = new ConcurrentQueue<string>();

        public static void Trace(string source, string message)
        {
            // Logger.Debug($"[{source}] [{Thread.CurrentThread.ManagedThreadId}] {message}");
            // Events.Enqueue($"[{DateTime.Now:O}] [{Thread.CurrentThread.ManagedThreadId}] [{source}] {message}");
            // Events.Enqueue($"[{Thread.CurrentThread.ManagedThreadId}] [{source}] {message}");
            Events.Enqueue($"[{source}] {message}");
        }

        public TlsHandler(TlsSettings settings)
            : this(stream => new SslStream(stream, true), settings)
        {
        }

        public TlsHandler(Func<Stream, SslStream> sslStreamFactory, TlsSettings settings)
        {
            Contract.Requires(sslStreamFactory != null);
            Contract.Requires(settings != null);

            this.settings = settings;
            this.closeFuture = new TaskCompletionSource();
            this.mediationStream = new MediationStream(this);
            this.sslStream = sslStreamFactory(this.mediationStream);
        }

        public static TlsHandler Client(string targetHost) => new TlsHandler(new ClientTlsSettings(targetHost));

        public static TlsHandler Client(string targetHost, X509Certificate clientCertificate) => new TlsHandler(new ClientTlsSettings(targetHost, new List<X509Certificate>{ clientCertificate }));
 
        public static TlsHandler Server(X509Certificate certificate) => new TlsHandler(new ServerTlsSettings(certificate));

        // using workaround mentioned here: https://github.com/dotnet/corefx/issues/4510
        public X509Certificate2 LocalCertificate => this.sslStream.LocalCertificate as X509Certificate2 ?? new X509Certificate2(this.sslStream.LocalCertificate?.Export(X509ContentType.Cert));

        public X509Certificate2 RemoteCertificate => this.sslStream.RemoteCertificate as X509Certificate2 ?? new X509Certificate2(this.sslStream.RemoteCertificate?.Export(X509ContentType.Cert));

        bool IsServer => this.settings is ServerTlsSettings;

        public override void ChannelActive(IChannelHandlerContext context)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.ChannelActive)}, isServer: {this.IsServer}");
            
            base.ChannelActive(context);

            if (!this.IsServer)
            {
                this.EnsureAuthenticated();
            }
        }

        public override void ChannelInactive(IChannelHandlerContext context)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.ChannelInactive)}, isServer: {this.IsServer}");
            
            // Make sure to release SslStream,
            // and notify the handshake future if the connection has been closed during handshake.
            this.HandleFailure(ChannelClosedException);

            base.ChannelInactive(context);
        }

        public override void ExceptionCaught(IChannelHandlerContext context, Exception exception)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.ExceptionCaught)}, exception: {exception}");
            if (this.IgnoreException(exception))
            {
                // Close the connection explicitly just in case the transport
                // did not close the connection automatically.
                if (context.Channel.Active)
                {
                    context.CloseAsync();
                }
            }
            else
            {
                base.ExceptionCaught(context, exception);
            }
        }

        bool IgnoreException(Exception t)
        {
            if (t is ObjectDisposedException && this.closeFuture.Task.IsCompleted)
            {
                Trace(nameof(TlsHandler), $"{nameof(this.IgnoreException)}");
                return true;
            }
            return false;
        }

        public override void HandlerAdded(IChannelHandlerContext context)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.HandlerAdded)}");
            
            base.HandlerAdded(context);
            this.capturedContext = context;
            this.pendingUnencryptedWrites = new BatchingPendingWriteQueue(context, UnencryptedWriteBatchSize);
            if (context.Channel.Active && !this.IsServer)
            {
                // todo: support delayed initialization on an existing/active channel if in client mode
                this.EnsureAuthenticated();
            }
        }

        protected override void HandlerRemovedInternal(IChannelHandlerContext context)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.HandlerRemovedInternal)}, pendingUnencryptedWrites.IsEmpty: {this.pendingUnencryptedWrites.IsEmpty}");
            if (!this.pendingUnencryptedWrites.IsEmpty)
            {
                // Check if queue is not empty first because create a new ChannelException is expensive
                this.pendingUnencryptedWrites.RemoveAndFailAll(new ChannelException("Write has failed due to TlsHandler being removed from channel pipeline."));
            }
        }

        public override Task CloseAsync(IChannelHandlerContext context)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.CloseAsync)}");
            
            this.closeFuture.TryComplete();
            this.sslStream.Dispose();
            return base.CloseAsync(context);
        }

        void HandleFailure(Exception cause)
        {
            // Release all resources such as internal buffers that SSLEngine
            // is managing.
            
            Trace(nameof(TlsHandler), $"{nameof(this.HandleFailure)}, cause: {cause}");

            this.mediationStream.Dispose();
            try
            {
                this.sslStream.Dispose();
            }
            catch (Exception)
            {
                // todo: evaluate following:
                // only log in Debug mode as it most likely harmless and latest chrome still trigger
                // this all the time.
                //
                // See https://github.com/netty/netty/issues/1340
                //string msg = ex.Message;
                //if (msg == null || !msg.contains("possible truncation attack"))
                //{
                //    //Logger.Debug("{} SSLEngine.closeInbound() raised an exception.", ctx.channel(), e);
                //}
            }
            this.pendingSslStreamReadBuffer?.SafeRelease();
            this.pendingSslStreamReadBuffer = null;
            this.pendingSslStreamReadFuture = null;

            this.NotifyHandshakeFailure(cause);
            this.pendingUnencryptedWrites.RemoveAndFailAll(cause);
        }
    }

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

    static class TlsHandlerStateExtensions
    {
        public static bool Has(this TlsHandlerState value, TlsHandlerState testValue) => (value & testValue) == testValue;

        public static bool HasAny(this TlsHandlerState value, TlsHandlerState testValue) => (value & testValue) != 0;
    }
}