// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Handlers.Tls;

using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Threading;
using System.Threading.Tasks;
using DotNetty.Buffers;
using DotNetty.Codecs;
using DotNetty.Common.Utilities;
using DotNetty.Transport.Channels;
using TaskCompletionSource = DotNetty.Common.Concurrency.TaskCompletionSource;

partial class TlsHandler
{
    BatchingPendingWriteQueue pendingUnencryptedWrites;
    Task lastContextWriteTask;
    
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

    long wrap = 0;
    void Wrap(IChannelHandlerContext context)
    {
        Trace(nameof(TlsHandler), $"[{Interlocked.Increment(ref this.wrap)}] {nameof(this.Wrap)}");
        
        Contract.Assert(context == this.capturedContext);

        IByteBuffer buf = null;
        try
        {
            while (true)
            {
                List<object> messages = this.pendingUnencryptedWrites.Current;
                Trace(nameof(TlsHandler), $"[{Interlocked.Increment(ref this.wrap)}] {nameof(this.Wrap)} messages.Count: {messages?.Count}");
                
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
                    Trace(nameof(TlsHandler), $"[{Interlocked.Increment(ref this.wrap)}] {nameof(this.Wrap)} this.lastContextWriteTask != null");
                    
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
}