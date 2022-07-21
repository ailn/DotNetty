// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#if NET5_0_OR_GREATER
namespace DotNetty.Handlers.Tls
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.Contracts;
    using System.IO;
    using System.Threading;
    using System.Threading.Tasks;

    partial class TlsHandler
    {
        sealed class MediationStreamNet : MediationStreamBase
        {
            readonly CompositeSource source = new CompositeSource();
            TaskCompletionSource<int> readCompletionSource;
            Memory<byte> sslOwnedMemory;
            int readByteCount;

            public MediationStreamNet(TlsHandler owner)
                : base(owner)
            {
            }

            public override bool SourceIsReadable
            {
                get
                {
                    lock (this)
                    {
                        return this.source?.IsReadable ?? false;
                    }
                }
            }

            public override int SourceReadableBytes
            {
                get
                {
                    lock (this)
                    {
                        return this.source.GetTotalReadableBytes();
                    }
                }
            }

            public override void SetSource(byte[] source, int offset)
            {
                lock (this)
                {
                    Trace(nameof(MediationStream), $"{nameof(this.SetSource)} source.Length: {source.Length}, offset: {offset}");
                    this.source.AddSource(source, offset);
                }
            }
            
            public override void ResetSource()
            {
                lock (this)
                {
                    Trace(nameof(MediationStream), $"{nameof(this.ResetSource)}");
                    this.source.CleanUp();
                }
            }

            public override void ExpandSource(int count)
            {
                lock (this)
                {
                    Trace(nameof(MediationStream), $"{nameof(this.ExpandSource)} count: {count}");

                    this.source.Expand(count);

                    Memory<byte> sslMemory = this.sslOwnedMemory;
                    if (sslMemory.IsEmpty)
                    {
                        // there is no pending read operation - keep for future
                        return;
                    }
                    this.sslOwnedMemory = default;

                    this.readByteCount = this.ReadFromInput(sslMemory);
                    // hack: this tricks SslStream's continuation to run synchronously instead of dispatching to TP. Remove once Begin/EndRead are available. 
                    new Task(
                            ms =>
                            {
                                var self = (MediationStreamNet)ms;
                                TaskCompletionSource<int> p = self.readCompletionSource;
                                self.readCompletionSource = null;
                                p.TrySetResult(self.readByteCount);
                            },
                            this)
                        .RunSynchronously(TaskScheduler.Default);
                }
            }

            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = new CancellationToken())
            {
                lock (this)
                {
                    if (this.SourceIsReadable)
                    {
                        Trace(nameof(MediationStream), $"{nameof(this.ReadAsync)} buffer.Length: {buffer.Length}, SourceIsReadable: {this.SourceIsReadable}. ReadFromInput");

                        // we have the bytes available upfront - write out synchronously
                        int read = this.ReadFromInput(buffer);
                        return new ValueTask<int>(read);
                    }

                    Trace(nameof(MediationStream), $"{nameof(this.ReadAsync)} buffer.Length: {buffer.Length},  SourceIsReadable: {this.SourceIsReadable}. readCompletionSource");

                    Contract.Assert(this.sslOwnedMemory.IsEmpty);
                    // take note of buffer - we will pass bytes there once available
                    this.sslOwnedMemory = buffer;
                    this.readCompletionSource = new TaskCompletionSource<int>();
                    return new ValueTask<int>(this.readCompletionSource.Task);
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

            int ReadFromInput(Memory<byte> destination)
            {
                int read = this.source.Read(destination);
                Trace(nameof(MediationStream), $"{nameof(this.ReadFromInput)} buffer.Length: {destination.Length}, read: {read}");
                return read;
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

            #region Source

            sealed class Source
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

                public int Read(Memory<byte> destination)
                {
                    int readableBytes = this.ReadableBytes;
                    int len = Math.Min(readableBytes, destination.Length);
                    new ReadOnlySpan<byte>(this.input, this.startOffset + this.offset, len).CopyTo(destination.Span);
                    this.offset += len;
                    return len;
                }
            }

            sealed class CompositeSource
            {
                // Why not List?
                // 1. It's unlikely this list to grow more than 2-3 nodes. In fact in most cases it'll have one element only
                // 2. Cleanup removes from head, so it's cheaper compared to List which shifts elements in this case. 
                readonly LinkedList<Source> sources = new LinkedList<Source>();

                public bool IsReadable
                {
                    get
                    {
                        // The composite source is readable if any readable sources, so
                        // it's enough to check on last one as we always AddLast
                        LinkedListNode<Source> last = this.sources.Last;
                        return last != null && last.Value.IsReadable;
                    }
                }

                public void AddSource(byte[] input, int offset)
                {
                    // Always add to the tail
                    this.sources.AddLast(new Source(input, offset));
                }

                public void Expand(int count)
                {
                    // Always expand the last added source
                    this.sources.Last?.Value.Expand(count);
                }

                public int GetTotalReadableBytes()
                {
                    int count = 0;
                    LinkedListNode<Source> node = this.sources.First;
                    while (node != null)
                    {
                        count += node.Value.ReadableBytes;
                        node = node.Next;
                    }

                    return count;
                }

                // Read from all readable sources to the destination starting from head (oldest)
                public int Read(Memory<byte> destination)
                {
                    int totalRead = 0;

                    LinkedListNode<Source> node = this.sources.First;
                    while (node != null && totalRead < destination.Length)
                    {
                        Source source = node.Value;
                        int read = source.Read(destination.Slice(totalRead, destination.Length - totalRead));
                        totalRead += read;

                        if (!source.IsReadable)
                        {
                            node = node.Next;
                            // Do not remove the node here as it can be expanded. Instead,
                            // remove in the CleanUp method below
                        }
                    }

                    return totalRead;
                }

                // Remove all not readable sources. Start from first as it's the oldest
                public void CleanUp()
                {
                    LinkedListNode<Source> node = this.sources.First;
                    while (node != null && !node.Value.IsReadable)
                    {
                        this.sources.RemoveFirst();
                        node = this.sources.First;
                    }
                }
            }

            #endregion
        }
    }
}
#endif