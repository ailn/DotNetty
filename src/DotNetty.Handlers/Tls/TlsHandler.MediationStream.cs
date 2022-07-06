// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Handlers.Tls;

using System;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using TaskCompletionSource = DotNetty.Common.Concurrency.TaskCompletionSource;

partial class TlsHandler
{
    sealed class MediationStream : Stream
    {
        readonly TlsHandler owner;
        byte[] input;
        int inputStartOffset;
        int inputOffset;
        int inputLength;
        TaskCompletionSource<int> readCompletionSource;
        ArraySegment<byte> sslOwnedBuffer;

        int readByteCount;

        public MediationStream(TlsHandler owner)
        {
            this.owner = owner;
        }

        public int SourceReadableBytes
        {
            get
            {
                lock (this.owner.sync)
                {
                    return this.inputLength - this.inputOffset;
                }
            }
        }

        public void SetSource(byte[] source, int offset)
        {
            Trace(nameof(MediationStream), $"{nameof(this.SetSource)} source.Length: {source.Length}, offset: {offset}");

            lock (this.owner.sync)
            {
                this.input = source;
                this.inputStartOffset = offset;
                this.inputOffset = 0;
                this.inputLength = 0;
            }
        }

        public void ResetSource()
        {
            Trace(nameof(MediationStream), $"{nameof(this.ResetSource)}");

            lock (this.owner.sync)
            {
                this.input = null;
                this.inputLength = 0;
            }
        }

        public bool ExpandSource(int count)
        {
            Trace(nameof(MediationStream), $"{nameof(this.ExpandSource)} count: {count}");

            Contract.Assert(this.input != null);

            lock (this.owner.sync)
            {
                this.inputLength += count;

                ArraySegment<byte> sslBuffer = this.sslOwnedBuffer;
                if (sslBuffer.Array == null)
                {
                    Trace(nameof(MediationStream), $"{nameof(this.ExpandSource)} there is no pending read operation - keep for future");
                    // there is no pending read operation - keep for future
                    return false;
                }

                this.sslOwnedBuffer = default(ArraySegment<byte>);
                this.readByteCount = this.ReadFromInput(sslBuffer.Array, sslBuffer.Offset, sslBuffer.Count);

                // hack: this tricks SslStream's continuation to run synchronously instead of dispatching to TP. Remove once Begin/EndRead are available. 
                new Task(OnReadComplete, this).RunSynchronously(TaskScheduler.Default);
                return true;
            }
        }

        static void OnReadComplete(object state)
        {
            var self = (MediationStream)state;
            Trace(nameof(MediationStream), $"{nameof(self.ExpandSource)} Complete readCompletionSource");
            lock (self.owner.sync)
            {
                TaskCompletionSource<int> p = self.readCompletionSource;
                self.readCompletionSource = null;
                p.TrySetResult(self.readByteCount);
            }
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Trace(nameof(MediationStream), $"{nameof(this.ReadAsync)} buffer.Length: {buffer.Length}, offset: {offset}, count: {count}, SourceReadableBytes: {this.SourceReadableBytes}");

            lock (this.owner.sync)
            {
                if (this.SourceReadableBytes > 0)
                {
                    // we have the bytes available upfront - write out synchronously
                    int read = this.ReadFromInput(buffer, offset, count);
                    return Task.FromResult(read);
                }

                Trace(nameof(MediationStream), $"{nameof(this.ReadAsync)} Pending ExpandSource. SourceReadableBytes: {this.SourceReadableBytes}");
                Contract.Assert(this.sslOwnedBuffer.Array == null);
                // take note of buffer - we will pass bytes there once available
                this.sslOwnedBuffer = new ArraySegment<byte>(buffer, offset, count);
                
                Trace(nameof(MediationStream), $"{nameof(this.ReadAsync)} this.sslOwnedBuffer.Array.Length: {this.sslOwnedBuffer.Array?.Length}");
                
                this.readCompletionSource = new TaskCompletionSource<int>();
                return this.readCompletionSource.Task;
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Trace(nameof(MediationStream), $"{nameof(this.Write)} buffer.Length: {buffer.Length}, offset: {offset}, count: {count}");
            this.owner.FinishWrap(buffer, offset, count);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Trace(nameof(MediationStream), $"{nameof(this.WriteAsync)} buffer.Length: {buffer.Length}, offset: {offset}, count: {count}");
            return this.owner.FinishWrapNonAppDataAsync(buffer, offset, count);
        }

        int ReadFromInput(byte[] destination, int destinationOffset, int destinationCapacity)
        {
            Trace(nameof(MediationStream), $"{nameof(this.ReadFromInput)} destination.Length: {destination.Length}, destinationOffset: {destinationOffset}, destinationCapacity: {destinationCapacity}");

            Contract.Assert(destination != null);

            byte[] source = this.input;
            int readableBytes = this.SourceReadableBytes;
            int length = Math.Min(readableBytes, destinationCapacity);
            Buffer.BlockCopy(source, this.inputStartOffset + this.inputOffset, destination, destinationOffset, length);
            this.inputOffset += length;
            return length;
        }

        public override void Flush()
        {
            // NOOP: called on SslStream.Close
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing)
            {
                TaskCompletionSource<int> p = this.readCompletionSource;
                if (p != null)
                {
                    this.readCompletionSource = null;
                    p.TrySetResult(0);
                }
            }
        }

        #region plumbing

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        #endregion
    }
}