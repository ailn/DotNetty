// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Handlers.Tls
{
    using System;
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
    using DotNetty.Common.Internal.Logging;
    using DotNetty.Common.Utilities;
    using DotNetty.Transport.Channels;
    
    using TaskCompletionSource = DotNetty.Common.Concurrency.TaskCompletionSource;

    public sealed partial class TlsHandler
    {
        sealed class MediationStream : Stream
        {
            static readonly IInternalLogger Logger = InternalLoggerFactory.GetInstance<MediationStream>();
            
            readonly TlsHandler owner;
            byte[] input;
            int inputStartOffset;
            int inputOffset;
            int inputLength;
            TaskCompletionSource<int> readCompletionSource;
            ArraySegment<byte> sslOwnedBuffer;
#if NETSTANDARD2_0_OR_GREATER || NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
            int readByteCount;
#else
            SynchronousAsyncResult<int> syncReadResult;
            AsyncCallback readCallback;
            TaskCompletionSource writeCompletion;
            AsyncCallback writeCallback;
#endif
            
#if NET5_0_OR_GREATER
            readonly IEventExecutor executor;
#endif

            public MediationStream(TlsHandler owner, IEventExecutor executor = default)
            {
                this.owner = owner;
#if NET5_0_OR_GREATER
                this.executor = executor;
#endif
            }

            public int SourceReadableBytes => this.inputLength - this.inputOffset;

            public void SetSource(byte[] source, int offset)
            {
                this.input = source;
                this.inputStartOffset = offset;
                this.inputOffset = 0;
                this.inputLength = 0;
            }

            public void ResetSource()
            {
                this.input = null;
                this.inputLength = 0;
            }

            public void ExpandSource(int count)
            {
                Contract.Assert(this.input != null);

                this.inputLength += count;

                ArraySegment<byte> sslBuffer = this.sslOwnedBuffer;
                if (sslBuffer.Array == null)
                {
                    // there is no pending read operation - keep for future
                    return;
                }

                this.sslOwnedBuffer = default(ArraySegment<byte>);

#if NETSTANDARD2_0_OR_GREATER || NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
                this.readByteCount = this.ReadFromInput(sslBuffer.Array, sslBuffer.Offset, sslBuffer.Count);
                // hack: this tricks SslStream's continuation to run synchronously instead of dispatching to TP. Remove once Begin/EndRead are available. 
                new Task(
                        ms =>
                        {
                            var self = (MediationStream)ms;
                            TaskCompletionSource<int> p = self.readCompletionSource;
                            self.readCompletionSource = null;
                            p.TrySetResult(self.readByteCount);
                        },
                        this)
                    .RunSynchronously(TaskScheduler.Default);
#else
                int read = this.ReadFromInput(sslBuffer.Array, sslBuffer.Offset, sslBuffer.Count);

                TaskCompletionSource<int> promise = this.readCompletionSource;
                this.readCompletionSource = null;
                promise.TrySetResult(read);

                AsyncCallback callback = this.readCallback;
                this.readCallback = null;
                callback?.Invoke(promise.Task);
#endif
            }

#if NETSTANDARD2_0_OR_GREATER || NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
#if NET5_0_OR_GREATER
                if (!this.executor.InEventLoop)
                {
                    Logger.Debug($"{nameof(this.ReadAsync)} (NOT IN LOOP) Tid: {Thread.CurrentThread.ManagedThreadId} ...");

                    var tcs = new TaskCompletionSource<int>();
                    this.executor.Execute(
                        () =>
                        {
                            this.ReadInternalAsync(buffer, offset, count, cancellationToken).LinkOutcome(tcs);
                        });
                    return tcs.Task;
                }
#endif
                return this.ReadInternalAsync(buffer, offset, count, cancellationToken);
            }

            Task<int> ReadInternalAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                Logger.Debug($"{nameof(ReadInternalAsync)} Tid: {Thread.CurrentThread.ManagedThreadId}");
                
                if (this.SourceReadableBytes > 0)
                {
                    // we have the bytes available upfront - write out synchronously
                    int read = this.ReadFromInput(buffer, offset, count);
                    return Task.FromResult(read);
                }

                Contract.Assert(this.sslOwnedBuffer.Array == null);
                // take note of buffer - we will pass bytes there once available
                this.sslOwnedBuffer = new ArraySegment<byte>(buffer, offset, count);
                this.readCompletionSource = new TaskCompletionSource<int>();
                return this.readCompletionSource.Task;
            }
#else
            public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
            {
                Logger.Debug($"{nameof(BeginRead)} Tid: {Thread.CurrentThread.ManagedThreadId}");

                if (this.SourceReadableBytes > 0)
                {
                    // we have the bytes available upfront - write out synchronously
                    int read = this.ReadFromInput(buffer, offset, count);
                    var res = this.PrepareSyncReadResult(read, state);
                    callback?.Invoke(res);
                    return res;
                }

                Contract.Assert(this.sslOwnedBuffer.Array == null);
                // take note of buffer - we will pass bytes there once available
                this.sslOwnedBuffer = new ArraySegment<byte>(buffer, offset, count);
                this.readCompletionSource = new TaskCompletionSource<int>(state);
                this.readCallback = callback;
                return this.readCompletionSource.Task;
            }

            public override int EndRead(IAsyncResult asyncResult)
            {
                Logger.Debug($"{nameof(this.EndRead)} Tid: {Thread.CurrentThread.ManagedThreadId}");
                SynchronousAsyncResult<int> syncResult = this.syncReadResult;
                if (ReferenceEquals(asyncResult, syncResult))
                {
                    return syncResult.Result;
                }

                Debug.Assert(this.readCompletionSource == null || this.readCompletionSource.Task == asyncResult);
                Contract.Assert(!((Task<int>)asyncResult).IsCanceled);

                try
                {
                    return ((Task<int>)asyncResult).Result;
                }
                catch (AggregateException ex)
                {
                    ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
                    throw; // unreachable
                }
            }

            IAsyncResult PrepareSyncReadResult(int readBytes, object state)
            {
                // it is safe to reuse sync result object as it can't lead to leak (no way to attach to it via handle)
                SynchronousAsyncResult<int> result = this.syncReadResult ?? (this.syncReadResult = new SynchronousAsyncResult<int>());
                result.Result = readBytes;
                result.AsyncState = state;
                return result;
            }
#endif

            public override void Write(byte[] buffer, int offset, int count)
            {
                Logger.Debug($"{nameof(this.Write)} Tid: {Thread.CurrentThread.ManagedThreadId}");
                this.owner.FinishWrap(buffer, offset, count);
            }

            public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
#if NET5_0_OR_GREATER
                if (!this.executor.InEventLoop)
                {
                    Logger.Debug($"{nameof(this.WriteAsync)} (NOT IN LOOP) Tid: {Thread.CurrentThread.ManagedThreadId} ...");

                    var tcs = new TaskCompletionSource();
                    this.executor.Execute(
                        () =>
                        {
                            Logger.Debug($"... {nameof(this.WriteAsync)} Tid: {Thread.CurrentThread.ManagedThreadId}");
                            this.owner.FinishWrapNonAppDataAsync(buffer, offset, count).LinkOutcome(tcs);
                        });
                    return tcs.Task;
                }
#endif
                Logger.Debug($"{nameof(this.WriteAsync)} Tid: {Thread.CurrentThread.ManagedThreadId}");
                return this.owner.FinishWrapNonAppDataAsync(buffer, offset, count);
            }

#if !(NETSTANDARD2_0_OR_GREATER || NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER)
            static readonly Action<Task, object> WriteCompleteCallback = HandleChannelWriteComplete;

            public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
            {
                Logger.Debug($"{nameof(this.BeginWrite)} Tid: {Thread.CurrentThread.ManagedThreadId}");

                Task task = this.WriteAsync(buffer, offset, count);
                switch (task.Status)
                {
                    case TaskStatus.RanToCompletion:
                        // write+flush completed synchronously (and successfully)
                        var result = new SynchronousAsyncResult<int>();
                        result.AsyncState = state;
                        callback?.Invoke(result);
                        return result;
                    default:
                        if (callback != null || state != task.AsyncState)
                        {
                            Contract.Assert(this.writeCompletion == null);
                            this.writeCallback = callback;
                            var tcs = new TaskCompletionSource(state);
                            this.writeCompletion = tcs;
                            task.ContinueWith(WriteCompleteCallback, this, TaskContinuationOptions.ExecuteSynchronously);
                            return tcs.Task;
                        }
                        else
                        {
                            return task;
                        }
                }
            }

            static void HandleChannelWriteComplete(Task writeTask, object state)
            {
                var self = (MediationStream)state;

                AsyncCallback callback = self.writeCallback;
                self.writeCallback = null;

                var promise = self.writeCompletion;
                self.writeCompletion = null;

                switch (writeTask.Status)
                {
                    case TaskStatus.RanToCompletion:
                        promise.TryComplete();
                        break;
                    case TaskStatus.Canceled:
                        promise.TrySetCanceled();
                        break;
                    case TaskStatus.Faulted:
                        promise.TrySetException(writeTask.Exception);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException("Unexpected task status: " + writeTask.Status);
                }

                callback?.Invoke(promise.Task);
            }

            public override void EndWrite(IAsyncResult asyncResult)
            {
                Logger.Debug($"{nameof(this.EndWrite)} Tid: {Thread.CurrentThread.ManagedThreadId}");
                if (asyncResult is SynchronousAsyncResult<int>)
                {
                    return;
                }

                try
                {
                    ((Task)asyncResult).Wait();
                }
                catch (AggregateException ex)
                {
                    ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
                    throw;
                }
            }
#endif

            int ReadFromInput(byte[] destination, int destinationOffset, int destinationCapacity)
            {
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

#region sync result
            sealed class SynchronousAsyncResult<T> : IAsyncResult
            {
                public T Result { get; set; }

                public bool IsCompleted => true;

                public WaitHandle AsyncWaitHandle
                {
                    get { throw new InvalidOperationException("Cannot wait on a synchronous result."); }
                }

                public object AsyncState { get; set; }

                public bool CompletedSynchronously => true;
            }

#endregion
        }
    }
}