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
    using System.Runtime.CompilerServices;
    using System.Runtime.ExceptionServices;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Permissions;
    using System.Threading;
    using System.Threading.Tasks;
    using DotNetty.Buffers;
    using DotNetty.Codecs;
    using DotNetty.Common;
    using DotNetty.Common.Concurrency;
    using DotNetty.Common.Utilities;
    using DotNetty.Transport.Channels;
    using TaskCompletionSource = DotNetty.Common.Concurrency.TaskCompletionSource;

    public sealed partial class TlsHandler : ByteToMessageDecoder
    {
        readonly TlsSettings settings;
        const int FallbackReadBufferSize = 256;
        const int UnencryptedWriteBatchSize = 14 * 1024;

        static readonly Exception ChannelClosedException = new IOException("Channel is closed");
        static readonly Action<Task, object> HandshakeCompletionCallback = new Action<Task, object>(HandleHandshakeCompleted);

        readonly SslStream sslStream;
        readonly MediationStreamBase mediationStream;
        readonly TaskCompletionSource closeFuture;

        TlsHandlerState state;
        int packetLength;
        byte contentType;
        List<(int packetLength, byte type)> pendingDataPackets;
        volatile IChannelHandlerContext capturedContext;
        BatchingPendingWriteQueue pendingUnencryptedWrites;
        Task lastContextWriteTask;
        bool firedChannelRead;
        IByteBuffer pendingSslStreamReadBuffer;
        Task<int> pendingSslStreamReadFuture;

        public static readonly ConcurrentQueue<string> Events = new ConcurrentQueue<string>();
        public static void Trace(string source, string message)
        {
            // Logger.Debug($"[{source}] [{Thread.CurrentThread.ManagedThreadId}] {message}");
            // Events.Enqueue($"[{DateTime.Now:O}] [{Thread.CurrentThread.ManagedThreadId}] [{source}] {message}");
            Events.Enqueue($"[{Thread.CurrentThread.ManagedThreadId}] [{source}] {message}");
            // Events.Enqueue($"[{source}] {message}");
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
            this.mediationStream = MediationStreamBase.Create(this);
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
            Trace(nameof(TlsHandler), $"{nameof(this.ChannelInactive)}");
            
            // Make sure to release SslStream,
            // and notify the handshake future if the connection has been closed during handshake.
            this.HandleFailure(ChannelClosedException);

            base.ChannelInactive(context);
        }

        public override void ExceptionCaught(IChannelHandlerContext context, Exception exception)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.ExceptionCaught)}. Exception: {exception}");
            
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
                return true;
            }
            return false;
        }

        static void HandleHandshakeCompleted(Task task, object state)
        {
            var self = (TlsHandler)state;
            Trace(nameof(TlsHandler), $"{nameof(HandleHandshakeCompleted)}, state: {self.state}, task.Status: {task.Status}");

            if (self.capturedContext.Executor.InEventLoop)
            {
                HandleHandshakeCompletedInternal(task, self);
            }
            else
            {
                self.capturedContext.Executor.Execute(() => HandleHandshakeCompletedInternal(task, self));    
            }
        }

        static void HandleHandshakeCompletedInternal(Task task, TlsHandler self)
        {
            Trace(nameof(TlsHandler), $"{nameof(HandleHandshakeCompletedInternal)}, state: {self.state}, task.Status: {task.Status}");
            switch (task.Status)
            {
                case TaskStatus.RanToCompletion:
                {
                    TlsHandlerState oldState = self.state;

                    Contract.Assert(!oldState.HasAny(TlsHandlerState.AuthenticationCompleted));
                    self.state = (oldState | TlsHandlerState.Authenticated) & ~(TlsHandlerState.Authenticating | TlsHandlerState.FlushedBeforeHandshake);

                    self.capturedContext.FireUserEventTriggered(TlsHandshakeCompletionEvent.Success);
                    
                    ThreadLocalObjectList output = ThreadLocalObjectList.NewInstance();
                    try
                    {
                        self.Unwrap(self.capturedContext, Unpooled.Empty, 0, 0, new List<(int packetLength, byte type)>(0), output);
                    }
                    finally
                    {
                        for (int i = 0; i < output.Count; i++)
                        {
                            self.capturedContext.FireChannelRead(output[i]);
                        }
                        output.Return();
                    }
                    
                    if (oldState.Has(TlsHandlerState.ReadRequestedBeforeAuthenticated) && !self.capturedContext.Channel.Configuration.AutoRead)
                    {
                        self.capturedContext.Read();
                    }

                    if (oldState.Has(TlsHandlerState.FlushedBeforeHandshake))
                    {
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
            Trace(nameof(TlsHandler), $"{nameof(this.HandlerRemovedInternal)}");
            
            if (!this.pendingUnencryptedWrites.IsEmpty)
            {
                // Check if queue is not empty first because create a new ChannelException is expensive
                this.pendingUnencryptedWrites.RemoveAndFailAll(new ChannelException("Write has failed due to TlsHandler being removed from channel pipeline."));
            }
        }

        int decode;
        protected override void Decode(IChannelHandlerContext context, IByteBuffer input, List<object> output)
        {
            int startOffset = input.ReaderIndex;
            int endOffset = input.WriterIndex;
            int offset = startOffset;
            int totalLength = 0;

            Trace(nameof(TlsHandler), $"[{Interlocked.Increment(ref this.decode)}] {nameof(this.Decode)} input.ReaderIndex: {input.ReaderIndex}, input.WriterIndex: {input.WriterIndex}, output.Count: {output.Count}");

            List<(int, byte)> packetLengths;
            // if we calculated the length of the current SSL record before, use that information.
            if (this.packetLength > 0)
            {
                if (endOffset - startOffset < this.packetLength)
                {
                    // input does not contain a single complete SSL record
                    return;
                }
                else
                {
                    packetLengths = new List<(int, byte)>(4);
                    packetLengths.Add((this.packetLength, this.contentType));
                    offset += this.packetLength;
                    totalLength = this.packetLength;
                    this.packetLength = 0;
                }
            }
            else
            {
                packetLengths = new List<(int, byte)>(4);
            }

            bool nonSslRecord = false;

            while (totalLength < TlsUtils.MAX_ENCRYPTED_PACKET_LENGTH)
            {
                int readableBytes = endOffset - offset;
                if (readableBytes < TlsUtils.SSL_RECORD_HEADER_LENGTH)
                {
                    break;
                }

                int encryptedPacketLength = TlsUtils.GetEncryptedPacketLength(input, offset, out byte type);
                if (encryptedPacketLength == -1)
                {
                    nonSslRecord = true;
                    break;
                }

                Contract.Assert(encryptedPacketLength > 0);

                if (encryptedPacketLength > readableBytes)
                {
                    // wait until the whole packet can be read
                    this.packetLength = encryptedPacketLength;
                    this.contentType = type;
                    break;
                }

                int newTotalLength = totalLength + encryptedPacketLength;
                if (newTotalLength > TlsUtils.MAX_ENCRYPTED_PACKET_LENGTH)
                {
                    // Don't read too much.
                    break;
                }

                // 1. call unwrap with packet boundaries - call SslStream.ReadAsync only once.
                // 2. once we're through all the whole packets, switch to reading out using fallback sized buffer

                // We have a whole packet.
                // Increment the offset to handle the next packet.
                packetLengths.Add((encryptedPacketLength, type));
                offset += encryptedPacketLength;
                totalLength = newTotalLength;
            }

            if (totalLength > 0)
            {
                // The buffer contains one or more full SSL records.
                // Slice out the whole packet so unwrap will only be called with complete packets.
                // Also directly reset the packetLength. This is needed as unwrap(..) may trigger
                // decode(...) again via:
                // 1) unwrap(..) is called
                // 2) wrap(...) is called from within unwrap(...)
                // 3) wrap(...) calls unwrapLater(...)
                // 4) unwrapLater(...) calls decode(...)
                //
                // See https://github.com/netty/netty/issues/1534

                input.SkipBytes(totalLength);
                this.Unwrap(context, input, startOffset, totalLength, packetLengths, output);

                if (!this.firedChannelRead)
                {
                    // Check first if firedChannelRead is not set yet as it may have been set in a
                    // previous decode(...) call.
                    this.firedChannelRead = output.Count > 0;
                }
            }

            if (nonSslRecord)
            {
                // Not an SSL/TLS packet
                var ex = new NotSslRecordException(
                    "not an SSL/TLS record: " + ByteBufferUtil.HexDump(input));
                input.SkipBytes(input.ReadableBytes);
                context.FireExceptionCaught(ex);
                this.HandleFailure(ex);
            }
        }

        public override void ChannelReadComplete(IChannelHandlerContext ctx)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.ChannelReadComplete)}");
            
            // Discard bytes of the cumulation buffer if needed.
            this.DiscardSomeReadBytes();

            this.ReadIfNeeded(ctx);

            this.firedChannelRead = false;
            ctx.FireChannelReadComplete();
        }

        void ReadIfNeeded(IChannelHandlerContext ctx)
        {
            // if handshake is not finished yet, we need more data
            if (!ctx.Channel.Configuration.AutoRead && (!this.firedChannelRead || !this.state.HasAny(TlsHandlerState.AuthenticationCompleted)))
            {
                // No auto-read used and no message was passed through the ChannelPipeline or the handshake was not completed
                // yet, which means we need to trigger the read to ensure we will not stall
                ctx.Read();
            }
        }
        

        /// <summary>Unwraps inbound SSL records.</summary>
        void Unwrap(IChannelHandlerContext ctx, IByteBuffer packet, int offset, int length, List<(int packetLength, byte type)> packetLengths, List<object> output)
        {
            Contract.Requires(packetLengths.Count > 0 || this.pendingDataPackets != null);

            Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} offset: {offset}, length: {length}");

            //bool notifyClosure = false; // todo: netty/issues/137
            bool pending = false;

            IByteBuffer outputBuffer = null;

            try
            {
                int packetIndex = 0;

                if (packetLengths.Count > 0)
                {
                    ArraySegment<byte> inputIoBuffer = packet.GetIoBuffer(offset, length);
                    this.mediationStream.SetSource(inputIoBuffer.Array, inputIoBuffer.Offset);

                    while (!this.EnsureAuthenticated())
                    {
                        // Due to SslStream's implementation, it's possible that we expand after handshake completed. Hence, we
                        // need to make sure we call ReadFromSslStreamAsync for these packets later
                        (int packetLength, byte type) = packetLengths[packetIndex];
                        Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} contentType: {TlsUtils.FormatContentType(type)}");
                        this.mediationStream.ExpandSource(packetLength);

                        if (type == TlsUtils.SSL_CONTENT_TYPE_APPLICATION_DATA)
                        {
                            Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} App data but not authenticated. packetIndex: {packetIndex}, count: {packetLengths.Count} ");
                            this.pendingDataPackets = this.pendingDataPackets ?? new List<(int packetLength, byte type)>(8);
                            this.pendingDataPackets.Add((packetLength, type));
                        }

                        if (++packetIndex == packetLengths.Count)
                        {
                            return;
                        }
                    }
                }

                Task<int> currentReadFuture = this.pendingSslStreamReadFuture;

                int outputBufferLength;

                if (currentReadFuture != null)
                {
                    // restoring context from previous read
                    Contract.Assert(this.pendingSslStreamReadBuffer != null);

                    outputBuffer = this.pendingSslStreamReadBuffer;
                    outputBufferLength = outputBuffer.WritableBytes;

                    this.pendingSslStreamReadFuture = null;
                    this.pendingSslStreamReadBuffer = null;
                }
                else
                {
                        outputBufferLength = 0;
                }

                // go through packets one by one (because SslStream does not consume more than 1 packet at a time)
                // account pendingDataPackets
                int skipExpandPacketCount = 0;
                if (this.pendingDataPackets != null)
                {
                    Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} PendingDataPackets: {this.pendingDataPackets.Count}");
                    // We already expanded the source for all pendingDataPackets, so skip expand further below
                    skipExpandPacketCount = this.pendingDataPackets.Count;

                    // add packetLengths to pending except already processed
                    for (int i = packetIndex; i < packetLengths.Count; i++)
                    {
                        this.pendingDataPackets.Add(packetLengths[i]);
                    }

                    packetLengths = this.pendingDataPackets;
                    this.pendingDataPackets = null;
                    packetIndex = 0;
                }

                for (; packetIndex < packetLengths.Count; packetIndex++)
                {
                    int currentPacketLength = packetLengths[packetIndex].packetLength;

                    if (--skipExpandPacketCount < 0)
                    {
                        // For pending packets we already expended, so skip expand 
                        this.mediationStream.ExpandSource(currentPacketLength);
                    }

                    if (currentReadFuture != null)
                    {
                        // there was a read pending already, so we make sure we completed that first

                        if (!currentReadFuture.IsCompleted)
                        {
                            // we did feed the whole current packet to SslStream yet it did not produce any result -> move to the next packet in input
                            Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} ReadFromSslStreamAsync currentReadFuture.IsCompleted: false");
                            continue;
                        }

                        int read = currentReadFuture.Result;
                        Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} ReadFromSslStreamAsync currentReadFuture.Result: {currentReadFuture.Result}");

                        if (read == 0)
                        {
                            //Stream closed
                            return;
                        }

                        // Now output the result of previous read and decide whether to do an extra read on the same source or move forward
                        AddBufferToOutput(outputBuffer, read, output);

                        currentReadFuture = null;
                        outputBuffer = null;
                        if (!this.mediationStream.SourceIsReadable)
                        {
                            // we just made a frame available for reading but there was already pending read so SslStream read it out to make further progress there

                            if (read < outputBufferLength)
                            {
                                // SslStream returned non-full buffer and there's no more input to go through ->
                                // typically it means SslStream is done reading current frame so we skip
                                continue;
                            }

                            // we've read out `read` bytes out of current packet to fulfil previously outstanding read
                            outputBufferLength = currentPacketLength - read;
                            if (outputBufferLength <= 0)
                            {
                                // after feeding to SslStream current frame it read out more bytes than current packet size
                                outputBufferLength = FallbackReadBufferSize;
                            }
                        }
                        else
                        {
                            // SslStream did not get to reading current frame so it completed previous read sync
                            // and the next read will likely read out the new frame
                            outputBufferLength = currentPacketLength;
                        }
                    }
                    else
                    {
                        // there was no pending read before so we estimate buffer of `currentPacketLength` bytes to be sufficient
                        outputBufferLength = currentPacketLength;
                    }

                    outputBuffer = ctx.Allocator.Buffer(outputBufferLength);
                    currentReadFuture = this.ReadFromSslStreamAsync(outputBuffer, outputBufferLength);
                }

                // read out the rest of SslStream's output (if any) at risk of going async
                // using FallbackReadBufferSize - buffer size we're ok to have pinned with the SslStream until it's done reading
                while (true)
                {
                    if (currentReadFuture != null)
                    {
                        if (!currentReadFuture.IsCompleted)
                        {
                            Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} ReadFromSslStreamAsync currentReadFuture.IsCompleted: false");
                            break;
                        }

                        int read = currentReadFuture.Result;
                        Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} ReadFromSslStreamAsync currentReadFuture.Result: {currentReadFuture.Result}");
                        AddBufferToOutput(outputBuffer, read, output);
                    }

                    outputBuffer = ctx.Allocator.Buffer(FallbackReadBufferSize);
                    currentReadFuture = this.ReadFromSslStreamAsync(outputBuffer, FallbackReadBufferSize);
                }

                pending = true;
                this.pendingSslStreamReadBuffer = outputBuffer;
                this.pendingSslStreamReadFuture = currentReadFuture;
            }
            catch (Exception ex)
            {
                this.HandleFailure(ex);
                throw;
            }
            finally
            {
                this.mediationStream.ResetSource();
                if (!pending && outputBuffer != null)
                {
                    if (outputBuffer.IsReadable())
                    {
                        output.Add(outputBuffer);
                    }
                    else
                    {
                        outputBuffer.SafeRelease();
                    }
                }
            }
        }

        static void AddBufferToOutput(IByteBuffer outputBuffer, int length, List<object> output)
        {
            Contract.Assert(length > 0);
            output.Add(outputBuffer.SetWriterIndex(outputBuffer.WriterIndex + length));
        }

        Task<int> ReadFromSslStreamAsync(IByteBuffer outputBuffer, int outputBufferLength)
        {
            Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.ReadFromSslStreamAsync)}({outputBufferLength})");
            ArraySegment<byte> outlet = outputBuffer.GetIoBuffer(outputBuffer.WriterIndex, outputBufferLength);
            return this.sslStream.ReadAsync(outlet.Array, outlet.Offset, outlet.Count);
        }

        public override void Read(IChannelHandlerContext context)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.Read)}");

            TlsHandlerState oldState = this.state;
            if (!oldState.HasAny(TlsHandlerState.AuthenticationCompleted))
            {
                this.state = oldState | TlsHandlerState.ReadRequestedBeforeAuthenticated;
            }

            context.Read();
        }

        bool EnsureAuthenticated()
        {
            Trace(nameof(TlsHandler), $"{nameof(this.EnsureAuthenticated)} state: {this.state}");
            
            TlsHandlerState oldState = this.state;
            if (!oldState.HasAny(TlsHandlerState.AuthenticationStarted))
            {
                this.state = oldState | TlsHandlerState.Authenticating;
                if (this.IsServer)
                {
                    Trace(nameof(TlsHandler), $"AuthenticateAsServerAsync state: {this.state}");
                    
                    var serverSettings = (ServerTlsSettings)this.settings;
                    this.sslStream.AuthenticateAsServerAsync(serverSettings.Certificate, serverSettings.NegotiateClientCertificate, serverSettings.EnabledProtocols, serverSettings.CheckCertificateRevocation)
                        .ContinueWith(HandshakeCompletionCallback, this, TaskContinuationOptions.ExecuteSynchronously);
                }
                else
                {
                    Trace(nameof(TlsHandler), $"AuthenticateAsClientAsync state: {this.state}");
                    
                    var clientSettings = (ClientTlsSettings)this.settings;
                    this.sslStream.AuthenticateAsClientAsync(clientSettings.TargetHost, clientSettings.X509CertificateCollection, clientSettings.EnabledProtocols, clientSettings.CheckCertificateRevocation)
                        .ContinueWith(HandshakeCompletionCallback, this, TaskContinuationOptions.ExecuteSynchronously);
                }
                return false;
            }

            return oldState.Has(TlsHandlerState.Authenticated);
        }

        public override Task WriteAsync(IChannelHandlerContext context, object message)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.WriteAsync)} message: {message}");

            if (!(message is IByteBuffer))
            {
                return TaskEx.FromException(new UnsupportedMessageTypeException(message, typeof(IByteBuffer)));
            }

            return this.pendingUnencryptedWrites.Add(message);
        }

        public override void Flush(IChannelHandlerContext context)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.Flush)}");

            if (this.pendingUnencryptedWrites.IsEmpty)
            {
                this.pendingUnencryptedWrites.Add(Unpooled.Empty);
            }

            if (!this.EnsureAuthenticated())
            {
                this.state |= TlsHandlerState.FlushedBeforeHandshake;
                return;
            }

            try
            {
                this.Wrap(context);
            }
            finally
            {
                // We may have written some parts of data before an exception was thrown so ensure we always flush.
                context.Flush();
            }
        }

        int wrap;
        void Wrap(IChannelHandlerContext context)
        {
            Contract.Assert(context == this.capturedContext);
            
            Trace(nameof(TlsHandler), $"[{Interlocked.Increment(ref this.wrap)}] {nameof(this.Wrap)}");

            IByteBuffer buf = null;
            try
            {
                while (true)
                {
                    List<object> messages = this.pendingUnencryptedWrites.Current;
                    if (messages == null || messages.Count == 0)
                    {
                        break;
                    }

                    if (messages.Count == 1)
                    {
                        buf = (IByteBuffer)messages[0];
                    }
                    else
                    {
                        buf = context.Allocator.Buffer((int)this.pendingUnencryptedWrites.CurrentSize);
                        foreach (IByteBuffer buffer in messages)
                        {
                            buffer.ReadBytes(buf, buffer.ReadableBytes);
                            buffer.Release();
                        }
                    }

                    buf.ReadBytes(this.sslStream, buf.ReadableBytes); // this leads to FinishWrap being called 0+ times
                    buf.Release();

                    TaskCompletionSource promise = this.pendingUnencryptedWrites.Remove();
                    Task task = this.lastContextWriteTask;
                    if (task != null)
                    {
                        task.LinkOutcome(promise);
                        this.lastContextWriteTask = null;
                    }
                    else
                    {
                        promise.TryComplete();
                    }
                }
            }
            catch (Exception ex)
            {
                buf.SafeRelease();
                this.HandleFailure(ex);
                throw;
            }
        }

        void FinishWrap(byte[] buffer, int offset, int count)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.FinishWrap)} buffer.Length: {buffer.Length}, offset: {offset}, count: {count}");
            
            IByteBuffer output;
            if (count == 0)
            {
                output = Unpooled.Empty;
            }
            else
            {
                output = this.capturedContext.Allocator.Buffer(count);
                output.WriteBytes(buffer, offset, count);
            }

            this.lastContextWriteTask = this.capturedContext.WriteAsync(output);
        }

        Task FinishWrapNonAppDataAsync(byte[] buffer, int offset, int count)
        {
            Trace(nameof(TlsHandler), $"{nameof(this.FinishWrapNonAppDataAsync)} buffer.Length: {buffer.Length}, offset: {offset}, count: {count}");
            
            var future = this.capturedContext.WriteAndFlushAsync(Unpooled.WrappedBuffer(buffer, offset, count));
            this.ReadIfNeeded(this.capturedContext);
            return future;
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
            
            Trace(nameof(TlsHandler), $"{nameof(HandleFailure)}, cause: {cause}");

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

        void NotifyHandshakeFailure(Exception cause)
        {
            if (!this.state.HasAny(TlsHandlerState.AuthenticationCompleted))
            {
                // handshake was not completed yet => TlsHandler react to failure by closing the channel
                this.state = (this.state | TlsHandlerState.FailedAuthentication) & ~TlsHandlerState.Authenticating;
                this.capturedContext.FireUserEventTriggered(new TlsHandshakeCompletionEvent(cause));
                this.CloseAsync(this.capturedContext);
            }
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