// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Handlers.Tls
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Diagnostics.Contracts;
    using System.Dynamic;
    using System.IO;
    using System.Runtime.ExceptionServices;
    using System.Threading;
    using System.Threading.Tasks;
    using DotNetty.Buffers;
    using DotNetty.Common;
    using DotNetty.Common.Internal;
    using DotNetty.Common.Utilities;
    using TaskCompletionSource = DotNetty.Common.Concurrency.TaskCompletionSource;

    partial class TlsHandler
    {
        class Source
        {
            readonly byte[] input;
            readonly int startOffset;
            int offset;
            int length;

            public Source(byte[] input, int offset)
            {
                this.input = input;
                this.startOffset = offset;
                this.offset = 0;
                this.length = 0;
            }
            
            public int ReadableBytes => this.length - this.offset;
            public bool IsReadable => this.ReadableBytes > 0;

            public void Expand(int count)
            {
                this.length += count;
                
                Contract.Assert(this.length <= this.input.Length);
            }
            
            public int Read(byte[] destination, int destinationOffset, int destinationCapacity)
            {
                Contract.Assert(destination != null);

                int readableBytes = this.ReadableBytes;
                int len = Math.Min(readableBytes, destinationCapacity);
                Buffer.BlockCopy(this.input, this.startOffset + this.offset, destination, destinationOffset, len);
                this.offset += len;
                return len;
            }
        }

        class CompositeSource
        {
            readonly LinkedList<Source> queue = new LinkedList<Source>();

            public bool IsReadable
            {
                get
                {
                    LinkedListNode<Source> last = this.queue.Last;
                    return last != null && last.Value.IsReadable;
                }
            }

            public void AddSource(byte[] input, int offset)
            {
                this.queue.AddLast(new Source(input, offset));
            }

            public void Expand(int count)
            {
                this.queue.Last?.Value.Expand(count);
            }

            public int TotalReadableBytes()
            {
                int count = 0;
                LinkedListNode<Source> node = this.queue.First;
                while (node != null)
                {
                    count += node.Value.ReadableBytes;
                    node = node.Next;
                }

                return count;
            }

            public int Read(byte[] destination, int destinationOffset, int destinationCapacity)
            {
                int totalRead = 0;

                LinkedListNode<Source> node = this.queue.First;
                while (node != null && totalRead < destinationCapacity)
                {
                    Source source = node.Value;
                    int read = source.Read(destination, destinationOffset + totalRead, destinationCapacity - totalRead);
                    totalRead += read;

                    if (!source.IsReadable)
                    {
                        node = node.Next;
                    }
                }

                return totalRead;
            }

            public void Reset()
            {
                // Remove all not readable sources 
                LinkedListNode<Source> first = this.queue.First;
                while (first != null && !first.Value.IsReadable)
                {
                    this.queue.RemoveFirst();
                    first = this.queue.First;
                }
            }
        }

        sealed class MediationStream2 : Stream
        {
            readonly TlsHandler owner;
            readonly CompositeSource source = new CompositeSource();
            TaskCompletionSource<int> readCompletionSource;
            ArraySegment<byte> sslOwnedBuffer;
            int readByteCount;

            public MediationStream2(TlsHandler owner)
            {
                this.owner = owner;
            }

            // public int SourceReadableBytes => this.source.ReadableBytes;
            public bool SourceIsReadable
            {
                get
                {
                    lock (this)
                    {
                        return this.source?.IsReadable ?? false;
                    }
                }
            }

            public int TotalReadableBytes
            {
                get
                {
                    lock (this)
                    {
                        return this.source.TotalReadableBytes();
                    }
                }
            }

            public void SetSource(byte[] source, int offset)
            {
                lock (this)
                {
                    Trace(nameof(MediationStream), $"{nameof(this.SetSource)} source.Length: {source.Length}, offset: {offset}");
                    this.source.AddSource(source, offset);    
                }
                
            }

            
            public void ResetSource()
            {
                lock (this)
                {
                    Trace(nameof(MediationStream), $"{nameof(this.ResetSource)}");
                    this.source.Reset();
                }
                // this.source = null;
            }

            public void ExpandSource(int count)
            {
                // Contract.Assert(this.source != null);

                lock (this)
                {
                    Trace(nameof(MediationStream), $"{nameof(this.ExpandSource)} count: {count}");

                    this.source.Expand(count);

                    ArraySegment<byte> sslBuffer = this.sslOwnedBuffer;
                    if (sslBuffer.Array == null)
                    {
                        // there is no pending read operation - keep for future
                        return;
                    }

                    this.sslOwnedBuffer = default(ArraySegment<byte>);

                    this.readByteCount = this.ReadFromInput(sslBuffer.Array, sslBuffer.Offset, sslBuffer.Count);
                    // hack: this tricks SslStream's continuation to run synchronously instead of dispatching to TP. Remove once Begin/EndRead are available. 
                    new Task(
                            ms =>
                            {
                                var self = (MediationStream2)ms;
                                TaskCompletionSource<int> p = self.readCompletionSource;
                                self.readCompletionSource = null;
                                p.TrySetResult(self.readByteCount);
                            },
                            this)
                        .RunSynchronously(TaskScheduler.Default);
                }
            }

            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                lock (this)
                {
                    if (this.SourceIsReadable)
                    {
                        Trace(nameof(MediationStream), $"{nameof(this.ReadAsync)} buffer.Length: {buffer.Length}, offset: {offset}, count: {count}, SourceIsReadable: {this.SourceIsReadable}. ReadFromInput");

                        // we have the bytes available upfront - write out synchronously
                        int read = this.ReadFromInput(buffer, offset, count);
                        return Task.FromResult(read);
                    }

                    Trace(nameof(MediationStream), $"{nameof(this.ReadAsync)} buffer.Length: {buffer.Length}, offset: {offset}, count: {count}, SourceIsReadable: {this.SourceIsReadable}. readCompletionSource");

                    Contract.Assert(this.sslOwnedBuffer.Array == null);
                    // take note of buffer - we will pass bytes there once available
                    this.sslOwnedBuffer = new ArraySegment<byte>(buffer, offset, count);
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
                Contract.Assert(destination != null);

                return this.source.Read(destination, destinationOffset, destinationCapacity);
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
}