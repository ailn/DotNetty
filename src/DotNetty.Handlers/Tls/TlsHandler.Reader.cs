// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Handlers.Tls;

using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Threading;
using System.Threading.Tasks;
using DotNetty.Buffers;
using DotNetty.Common.Utilities;
using DotNetty.Transport.Channels;

partial class TlsHandler
{
    int packetLength;
    bool firedChannelRead;
    
    public override void Read(IChannelHandlerContext context)
    {
        Trace(nameof(TlsHandler), $"{nameof(this.Read)}");

        lock (this.sync)
        {
            TlsHandlerState oldState = this.state;
            if (!oldState.HasAny(TlsHandlerState.AuthenticationCompleted))
            {
                this.state = oldState | TlsHandlerState.ReadRequestedBeforeAuthenticated;
            }
        }

        context.Read();
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

    int decode = 0;
    // protected override void Decode(IChannelHandlerContext context, IByteBuffer input, List<object> output)
    // {
    //     int startOffset = input.ReaderIndex;
    //     int endOffset = input.WriterIndex;
    //     int offset = startOffset;
    //     int totalLength = 0;
    //     
    //     Trace(nameof(TlsHandler), $"[{Interlocked.Increment(ref this.decode)}] {nameof(this.Decode)}, startOffset: {startOffset}, endOffset: {endOffset}, offset: {offset}, totalLength: {totalLength}; output.Count: {output.Count}");
    //
    //     List<int> packetLengths;
    //     // if we calculated the length of the current SSL record before, use that information.
    //     Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} this.packetLength: {this.packetLength}");
    //     if (this.packetLength > 0)
    //     {
    //         if (endOffset - startOffset < this.packetLength)
    //         {
    //             // input does not contain a single complete SSL record
    //             Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} input does not contain a single complete SSL record. endOffset - startOffset: {endOffset - startOffset}");
    //             return;
    //         }
    //         else
    //         {
    //             Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} endOffset - startOffset: {endOffset - startOffset}, this.packetLength: {this.packetLength}");
    //             packetLengths = new List<int>(4);
    //             packetLengths.Add(this.packetLength);
    //             offset += this.packetLength;
    //             totalLength = this.packetLength;
    //             this.packetLength = 0;
    //             Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} this.packetLength: {this.packetLength}, offset: {offset}, totalLength: {totalLength}");
    //         }
    //     }
    //     else
    //     {
    //         packetLengths = new List<int>(4);
    //     }
    //
    //     bool nonSslRecord = false;
    //
    //     while (totalLength < TlsUtils.MAX_ENCRYPTED_PACKET_LENGTH)
    //     {
    //         Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} totalLength ({totalLength}) < TlsUtils.MAX_ENCRYPTED_PACKET_LENGTH ({TlsUtils.MAX_ENCRYPTED_PACKET_LENGTH})");
    //         
    //         int readableBytes = endOffset - offset;
    //         if (readableBytes < TlsUtils.SSL_RECORD_HEADER_LENGTH)
    //         {
    //             Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} readableBytes ({readableBytes}) < TlsUtils.SSL_RECORD_HEADER_LENGTH ({TlsUtils.SSL_RECORD_HEADER_LENGTH})");
    //             break;
    //         }
    //
    //         int encryptedPacketLength = TlsUtils.GetEncryptedPacketLength(input, offset);
    //         Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} encryptedPacketLength: {encryptedPacketLength}");
    //         if (encryptedPacketLength == -1)
    //         {
    //             nonSslRecord = true;
    //             break;
    //         }
    //
    //         Contract.Assert(encryptedPacketLength > 0);
    //
    //         if (encryptedPacketLength > readableBytes)
    //         {
    //             Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} encryptedPacketLength ({encryptedPacketLength}) > readableBytes ({readableBytes})");
    //             
    //             // wait until the whole packet can be read
    //             this.packetLength = encryptedPacketLength;
    //             break;
    //         }
    //
    //         int newTotalLength = totalLength + encryptedPacketLength;
    //         if (newTotalLength > TlsUtils.MAX_ENCRYPTED_PACKET_LENGTH)
    //         {
    //             Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} newTotalLength ({newTotalLength}) > TlsUtils.MAX_ENCRYPTED_PACKET_LENGTH ({TlsUtils.MAX_ENCRYPTED_PACKET_LENGTH})");
    //             // Don't read too much.
    //
    //             return;
    //             // break;
    //         }
    //
    //         // 1. call unwrap with packet boundaries - call SslStream.ReadAsync only once.
    //         // 2. once we're through all the whole packets, switch to reading out using fallback sized buffer
    //
    //         // We have a whole packet.
    //         // Increment the offset to handle the next packet.
    //         packetLengths.Add(encryptedPacketLength);
    //         offset += encryptedPacketLength;
    //         totalLength = newTotalLength;
    //     }
    //
    //     if (totalLength > 0)
    //     {
    //         Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} totalLength ({totalLength}) > 0");
    //         
    //         // The buffer contains one or more full SSL records.
    //         // Slice out the whole packet so unwrap will only be called with complete packets.
    //         // Also directly reset the packetLength. This is needed as unwrap(..) may trigger
    //         // decode(...) again via:
    //         // 1) unwrap(..) is called
    //         // 2) wrap(...) is called from within unwrap(...)
    //         // 3) wrap(...) calls unwrapLater(...)
    //         // 4) unwrapLater(...) calls decode(...)
    //         //
    //         // See https://github.com/netty/netty/issues/1534
    //
    //         input.SkipBytes(totalLength);
    //         this.Unwrap(context, input, startOffset, totalLength, packetLengths, output);
    //
    //         if (!this.firedChannelRead)
    //         {
    //             // Check first if firedChannelRead is not set yet as it may have been set in a
    //             // previous decode(...) call.
    //             this.firedChannelRead = output.Count > 0;
    //         }
    //     }
    //
    //     if (nonSslRecord)
    //     {
    //         Trace(nameof(TlsHandler), $"{nameof(this.Decode)} nonSslRecord");
    //
    //         // Not an SSL/TLS packet
    //         var ex = new NotSslRecordException(
    //             "not an SSL/TLS record: " + ByteBufferUtil.HexDump(input));
    //         input.SkipBytes(input.ReadableBytes);
    //         context.FireExceptionCaught(ex);
    //         this.HandleFailure(ex);
    //     }
    //
    //     Trace(nameof(TlsHandler), $"{nameof(this.Decode)}Complete, output.Count: {output.Count}");
    // }

    protected override void Decode(IChannelHandlerContext context, IByteBuffer input, List<object> output)
    {
        Trace(nameof(TlsHandler), $"[{Interlocked.Increment(ref this.decode)}] {nameof(this.Decode)} input.ReaderIndex: {input.ReaderIndex}, input.WriterIndex: {input.WriterIndex}, output.Count: {output.Count}");

        int packetLength = this.packetLength;
        // if we calculated the length of the current SSL record before, use that information.
        Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} packetLength: {packetLength}");
        if (packetLength > 0)
        {
            if (input.ReadableBytes < packetLength)
            {
                // input does not contain a single complete SSL record
                Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} input does not contain a single complete SSL record.");
                return;
            }
        }
        else
        {
            // Get the packet length and wait until we get a packets worth of data to unwrap.
            int readableBytes = input.ReadableBytes;
            if (readableBytes < TlsUtils.SSL_RECORD_HEADER_LENGTH)
            {
                Trace(nameof(TlsHandler), $"[{Interlocked.Increment(ref this.decode)}] {nameof(this.Decode)} readableBytes ({readableBytes}) < TlsUtils.SSL_RECORD_HEADER_LENGTH ({TlsUtils.SSL_RECORD_HEADER_LENGTH})");
                return;
            }
            
            packetLength = TlsUtils.GetEncryptedPacketLength(input);
            Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} GetEncryptedPacketLength: {packetLength}");
            
            if (packetLength == -1)
            {
                Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} Not an SSL/TLS packet.");
                
                // Not an SSL/TLS packet
                var ex = new NotSslRecordException(
                    "not an SSL/TLS record: " + ByteBufferUtil.HexDump(input));
                input.SkipBytes(input.ReadableBytes);
                context.FireExceptionCaught(ex);
                this.HandleFailure(ex);
                return;
            }

            if (packetLength > readableBytes)
            {
                Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Decode)} packetLength ({packetLength}) > readableBytes ({readableBytes}).");
                
                // wait until the whole packet can be read
                this.packetLength = packetLength;
                return;
            }
        }

        // Reset the state of this class so we can get the length of the next packet. We assume the entire packet will
        // be consumed by the SSLEngine.
        this.packetLength = 0;

        if (this.Unwrap(context, input, input.ReaderIndex, packetLength))
        {
            input.SkipBytes(packetLength);
        }
    }
    
    bool Unwrap(IChannelHandlerContext ctx, IByteBuffer packet, int offset, int length)
    {
        Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} offset: {offset}, length: {length}");

        //bool notifyClosure = false; // todo: netty/issues/137
        bool pending = false;

        IByteBuffer outputBuffer = null;

        try
        {
            ArraySegment<byte> inputIoBuffer = packet.GetIoBuffer(offset, length);
            this.mediationStream.SetSource(inputIoBuffer.Array, inputIoBuffer.Offset);

            if (!this.EnsureAuthenticated())
            {
                Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} !this.EnsureAuthenticated()");
                
                return this.mediationStream.ExpandSource(length);
            }

            this.mediationStream.ExpandSource(length);

            Task<int> currentReadFuture = this.pendingSslStreamReadFuture;

            if (currentReadFuture != null)
            {
                Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} currentReadFuture != null");
                
                // restoring context from previous read
                Contract.Assert(this.pendingSslStreamReadBuffer != null);

                outputBuffer = this.pendingSslStreamReadBuffer;
                int outputBufferLength = outputBuffer.WritableBytes;
                
                Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} outputBufferLength: {outputBufferLength} (=outputBuffer.WritableBytes)");

                this.pendingSslStreamReadFuture = null;
                this.pendingSslStreamReadBuffer = null;
                
                // there was a read pending already, so we make sure we completed that first
                if (currentReadFuture.IsCompleted)
                {
                    int read = currentReadFuture.Result;
                    if (read == 0)
                    {
                        //Stream closed
                        Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} read == 0 - Stream closed");
                        // todo: NotifyClosePromise 
                        return true;
                    }

                    // Now output the result of previous read and decide whether to do an extra read on the same source or move forward
                    outputBuffer.SetWriterIndex(outputBuffer.WriterIndex + read);
                    this.firedChannelRead = true;
                    ctx.FireChannelRead(outputBuffer);

                    currentReadFuture = null;
                    outputBuffer = null;

                    if (0 >= this.mediationStream.SourceReadableBytes)
                    {
                        Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} 0 >= this.mediationStream.SourceReadableBytes");
                        // we just made a frame available for reading but there was already pending read so SslStream read it out to make further progress there

                        if (read < outputBufferLength)
                        {
                            Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} read ({read}) < outputBufferLength ({outputBufferLength})");
                            // SslStream returned non-full buffer and there's no more input to go through ->
                            // typically it means SslStream is done reading current frame so we skip
                            return true;
                        }

                        // we've read out `read` bytes out of current packet to fulfil previously outstanding read
                        outputBufferLength = length - read;
                        if (outputBufferLength <= 0)
                        {
                            Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} outputBufferLength ({outputBufferLength}) <= 0 -> outputBufferLength = FallbackReadBufferSize");
                            // after feeding to SslStream current frame it read out more bytes than current packet size
                            outputBufferLength = FallbackReadBufferSize;
                        }
                    }

                    outputBuffer = ctx.Allocator.Buffer(outputBufferLength);
                    currentReadFuture = this.ReadFromSslStreamAsync(outputBuffer, outputBufferLength);
                }
            }
            else
            {
                // there was no pending read before so we estimate buffer of `length` bytes to be sufficient
                outputBuffer = ctx.Allocator.Buffer(length);
                currentReadFuture = ReadFromSslStreamAsync(outputBuffer, length);
            }

            // read out the rest of SslStream's output (if any) at risk of going async
            // using FallbackReadBufferSize - buffer size we're ok to have pinned with the SslStream until it's done reading
            while (true)
            {
                if (currentReadFuture != null)
                {
                    if (!currentReadFuture.IsCompleted)
                    {
                        Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} !currentReadFuture.IsCompleted");
                        break;
                    }

                    int read = currentReadFuture.Result;
                    if (read == 0)
                    {
                        //Stream closed
                        Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} read == 0 - Stream closed");
                        // todo: NotifyClosePromise 
                        return true;
                    }
                    
                    outputBuffer.SetWriterIndex(outputBuffer.WriterIndex + read);
                    this.firedChannelRead = true;
                    ctx.FireChannelRead(outputBuffer);
                }

                outputBuffer = ctx.Allocator.Buffer(FallbackReadBufferSize);
                currentReadFuture = this.ReadFromSslStreamAsync(outputBuffer, FallbackReadBufferSize);
            }

            pending = true;
            this.pendingSslStreamReadBuffer = outputBuffer;
            this.pendingSslStreamReadFuture = currentReadFuture;

            return true;
        }
        catch (Exception ex)
        {
            this.HandleFailure(ex);
            throw;
        }
        finally
        {
            Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} Complete");
            this.mediationStream.ResetSource();
            if (!pending && outputBuffer != null)
            {
                if (outputBuffer.IsReadable())
                {
                    Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} ... Complete: outputBuffer.IsReadable() -> ctx.FireChannelRead(outputBuffer);");
                    this.firedChannelRead = true;
                    ctx.FireChannelRead(outputBuffer);
                }
                else
                {
                    Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} ... Complete: outputBuffer.SafeRelease();");
                    outputBuffer.SafeRelease();
                }
            }
        }
    }

    // /// <summary>Unwraps inbound SSL records.</summary>
    // void Unwrap(IChannelHandlerContext ctx, IByteBuffer packet, int offset, int length, List<int> packetLengths, List<object> output)
    // {
    //     Contract.Requires(packetLengths.Count > 0);
    //     
    //     Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} offset: {offset}, length: {length}, packetLengths.Count: {packetLengths.Count}, output.Count: {output.Count}");
    //
    //     //bool notifyClosure = false; // todo: netty/issues/137
    //     bool pending = false;
    //
    //     IByteBuffer outputBuffer = null;
    //
    //     try
    //     {
    //         ArraySegment<byte> inputIoBuffer = packet.GetIoBuffer(offset, length);
    //         this.mediationStream.SetSource(inputIoBuffer.Array, inputIoBuffer.Offset);
    //
    //         int packetIndex = 0;
    //
    //         while (!this.EnsureAuthenticated())
    //         {
    //             Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} !this.EnsureAuthenticated()");
    //             
    //             this.mediationStream.ExpandSource(packetLengths[packetIndex]);
    //             if (++packetIndex == packetLengths.Count)
    //             {
    //                 Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} ++packetIndex ({packetIndex}) == packetLengths.Count ({packetLengths.Count})");
    //                 return;
    //             }
    //         }
    //
    //         Task<int> currentReadFuture = this.pendingSslStreamReadFuture;
    //
    //         int outputBufferLength;
    //
    //         if (currentReadFuture != null)
    //         {
    //             Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} currentReadFuture != null");
    //             
    //             // restoring context from previous read
    //             Contract.Assert(this.pendingSslStreamReadBuffer != null);
    //
    //             outputBuffer = this.pendingSslStreamReadBuffer;
    //             outputBufferLength = outputBuffer.WritableBytes;
    //             
    //             Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} outputBufferLength: {outputBufferLength} (=outputBuffer.WritableBytes)");
    //
    //             this.pendingSslStreamReadFuture = null;
    //             this.pendingSslStreamReadBuffer = null;
    //         }
    //         else
    //         {
    //             outputBufferLength = 0;
    //         }
    //
    //         // go through packets one by one (because SslStream does not consume more than 1 packet at a time)
    //         for (; packetIndex < packetLengths.Count; packetIndex++)
    //         {
    //             int currentPacketLength = packetLengths[packetIndex];
    //             Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} currentPacketLength: {currentPacketLength}");
    //             this.mediationStream.ExpandSource(currentPacketLength);
    //
    //             if (currentReadFuture != null)
    //             {
    //                 // there was a read pending already, so we make sure we completed that first
    //
    //                 if (!currentReadFuture.IsCompleted)
    //                 {
    //                     // we did feed the whole current packet to SslStream yet it did not produce any result -> move to the next packet in input
    //                     Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} !currentReadFuture.IsCompleted");
    //                     continue;
    //                 }
    //
    //                 int read = currentReadFuture.Result;
    //
    //                 if (read == 0)
    //                 {
    //                     //Stream closed
    //                     Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} read == 0 - Stream closed");
    //                     return;
    //                 }
    //
    //                 // Now output the result of previous read and decide whether to do an extra read on the same source or move forward
    //                 AddBufferToOutput(outputBuffer, read, output);
    //
    //                 currentReadFuture = null;
    //                 outputBuffer = null;
    //                 if (this.mediationStream.SourceReadableBytes == 0)
    //                 {
    //                     Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} this.mediationStream.SourceReadableBytes == 0");
    //                     // we just made a frame available for reading but there was already pending read so SslStream read it out to make further progress there
    //
    //                     if (read < outputBufferLength)
    //                     {
    //                         Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} read ({read}) < outputBufferLength ({outputBufferLength})");
    //                         // SslStream returned non-full buffer and there's no more input to go through ->
    //                         // typically it means SslStream is done reading current frame so we skip
    //                         continue;
    //                     }
    //
    //                     // we've read out `read` bytes out of current packet to fulfil previously outstanding read
    //                     outputBufferLength = currentPacketLength - read;
    //                     if (outputBufferLength <= 0)
    //                     {
    //                         Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} outputBufferLength ({outputBufferLength}) <= 0 -> outputBufferLength = FallbackReadBufferSize");
    //                         // after feeding to SslStream current frame it read out more bytes than current packet size
    //                         outputBufferLength = FallbackReadBufferSize;
    //                     }
    //                 }
    //                 else
    //                 {
    //                     // SslStream did not get to reading current frame so it completed previous read sync
    //                     // and the next read will likely read out the new frame
    //                     outputBufferLength = currentPacketLength;
    //                 }
    //             }
    //             else
    //             {
    //                 // there was no pending read before so we estimate buffer of `currentPacketLength` bytes to be sufficient
    //                 outputBufferLength = currentPacketLength;
    //             }
    //
    //             outputBuffer = ctx.Allocator.Buffer(outputBufferLength);
    //             currentReadFuture = this.ReadFromSslStreamAsync(outputBuffer, outputBufferLength);
    //         }
    //
    //         // read out the rest of SslStream's output (if any) at risk of going async
    //         // using FallbackReadBufferSize - buffer size we're ok to have pinned with the SslStream until it's done reading
    //         while (true)
    //         {
    //             if (currentReadFuture != null)
    //             {
    //                 if (!currentReadFuture.IsCompleted)
    //                 {
    //                     Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} !currentReadFuture.IsCompleted");
    //                     break;
    //                 }
    //
    //                 int read = currentReadFuture.Result;
    //                 AddBufferToOutput(outputBuffer, read, output);
    //             }
    //
    //             outputBuffer = ctx.Allocator.Buffer(FallbackReadBufferSize);
    //             currentReadFuture = this.ReadFromSslStreamAsync(outputBuffer, FallbackReadBufferSize);
    //         }
    //
    //         pending = true;
    //         this.pendingSslStreamReadBuffer = outputBuffer;
    //         this.pendingSslStreamReadFuture = currentReadFuture;
    //     }
    //     catch (Exception ex)
    //     {
    //         this.HandleFailure(ex);
    //         throw;
    //     }
    //     finally
    //     {
    //         Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} Complete");
    //         this.mediationStream.ResetSource();
    //         if (!pending && outputBuffer != null)
    //         {
    //             if (outputBuffer.IsReadable())
    //             {
    //                 Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} ... Complete: outputBuffer.IsReadable() -> output.Add(outputBuffer);");
    //                 output.Add(outputBuffer);
    //             }
    //             else
    //             {
    //                 Trace(nameof(TlsHandler), $"[{this.decode}] {nameof(this.Unwrap)} ... Complete: outputBuffer.SafeRelease();");
    //                 outputBuffer.SafeRelease();
    //             }
    //         }
    //     }
    // }

    Task<int> ReadFromSslStreamAsync(IByteBuffer outputBuffer, int outputBufferLength)
    {
        Trace(nameof(TlsHandler), $"{nameof(this.ReadFromSslStreamAsync)} outputBuffer.WriterIndex: {outputBuffer.WriterIndex}, outputBufferLength: {outputBufferLength}");

        ArraySegment<byte> outlet = outputBuffer.GetIoBuffer(outputBuffer.WriterIndex, outputBufferLength);
        return this.sslStream.ReadAsync(outlet.Array, outlet.Offset, outlet.Count);
    }

    void ReadIfNeeded(IChannelHandlerContext ctx)
    {
        Trace(nameof(TlsHandler), $"{nameof(this.ReadIfNeeded)}");
        
        lock (this.sync)
        {
            // if handshake is not finished yet, we need more data
            if (!ctx.Channel.Configuration.AutoRead && 
                (!this.firedChannelRead || !this.state.HasAny(TlsHandlerState.AuthenticationCompleted)))
            {
                // No auto-read used and no message was passed through the ChannelPipeline or the handshake was not completed
                // yet, which means we need to trigger the read to ensure we will not stall
                Trace(nameof(TlsHandler), $"{nameof(this.ReadIfNeeded)} ctx.Read();");
                ctx.Read();
            }
        }
        
        Trace(nameof(TlsHandler), $"{nameof(this.ReadIfNeeded)} COMPLETE");
    }

    static void AddBufferToOutput(IByteBuffer outputBuffer, int length, List<object> output)
    {
        Trace(nameof(TlsHandler), $"{nameof(AddBufferToOutput)} outputBuffer.WriterIndex: {outputBuffer.WriterIndex}, length: {length}, output.Count: {output.Count}");
        
        Contract.Assert(length > 0);
        output.Add(outputBuffer.SetWriterIndex(outputBuffer.WriterIndex + length));
        
        Trace(nameof(TlsHandler), $"{nameof(AddBufferToOutput)} COMPLETE");
    }
}