﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace DotNetty.Handlers.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Net.Security;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using DotNetty.Buffers;
    using DotNetty.Common.Concurrency;
    using DotNetty.Handlers.Tls;
    using DotNetty.Tests.Common;
    using DotNetty.Transport.Channels;
    using DotNetty.Transport.Channels.Embedded;
    using Xunit;
    using Xunit.Abstractions;

    public class TlsHandlerTest : TestBase
    {
        static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(10);

        public TlsHandlerTest(ITestOutputHelper output)
            : base(output)
        {
        }

        public static IEnumerable<object[]> GetTlsReadTestData()
        {
            var random = new Random(Environment.TickCount);
            var lengthVariations =
                new[]
                {
                    new[] { 1 },
                    new[] { 2, 8000, 300 },
                    new[] { 100, 0, 1000 },
                    new[] { 4 * 1024 - 10, 1, 0, 1 },
                    new[] { 0, 24000, 0, 1000 },
                    new[] { 0, 4000, 0 },
                    new[] { 16 * 1024 - 100 },
                    Enumerable.Repeat(0, 30).Select(_ => random.Next(0, 17000)).ToArray()
                };
            var boolToggle = new[] { false, true };
            var protocols = new[]
            {
                Tuple.Create(SslProtocols.Tls, SslProtocols.Tls),
                Tuple.Create(SslProtocols.Tls11, SslProtocols.Tls11),
                Tuple.Create(SslProtocols.Tls12, SslProtocols.Tls12),
                Tuple.Create(SslProtocols.Tls12 | SslProtocols.Tls, SslProtocols.Tls12 | SslProtocols.Tls11),
                Tuple.Create(SslProtocols.Tls | SslProtocols.Tls12, SslProtocols.Tls | SslProtocols.Tls11)
            };
            var writeStrategyFactories = new Func<IWriteStrategy>[]
            {
                () => new AsIsWriteStrategy(),
                () => new BatchingWriteStrategy(1, TimeSpan.FromMilliseconds(20), true),
                () => new BatchingWriteStrategy(4096, TimeSpan.FromMilliseconds(20), true),
                () => new BatchingWriteStrategy(32 * 1024, TimeSpan.FromMilliseconds(20), false)
            };

            return
                from frameLengths in lengthVariations
                from isClient in boolToggle
                from writeStrategyFactory in writeStrategyFactories
                from protocol in protocols
                select new object[] { frameLengths, isClient, writeStrategyFactory(), protocol.Item1, protocol.Item2 };
        }

        [Fact]
        public async Task TlsRead2()
        {
            var executor = new SingleThreadEventExecutor("test executor", TimeSpan.FromMilliseconds(10));

            try
            {
                var writeTasks = new List<Task>();
                Tuple<EmbeddedChannel, SslStream> setup = await SetupStreamAndChannelAsync(
                    isClient: true,
                    executor,
                    new AsIsWriteStrategy(),
                    serverProtocol: SslProtocols.Tls12,
                    clientProtocol: SslProtocols.Tls12,
                    writeTasks: writeTasks);
            }
            finally
            {
                while (TlsHandler.Events.TryDequeue(out string msg))
                {
                    this.Output.WriteLine(msg);
                }
                await executor.ShutdownGracefullyAsync(TimeSpan.Zero, TimeSpan.Zero);
            }
        }

        [Fact]
        public async Task TlsRead1()
        {
            while (TlsHandler.Events.TryDequeue(out _))
            {
            }
            
            var executor = new SingleThreadEventExecutor("test executor", TimeSpan.FromMilliseconds(10));

            try
            {
                X509Certificate2 tlsCertificate = TestResourceHelper.GetTestCertificate();
                string targetHost = tlsCertificate.GetNameInfo(X509NameType.DnsName, false);

                var tlsHandler = new TlsHandler(
                    stream => new SslStream(stream, true, (sender, certificate, chain, errors) => true),
                    new ClientTlsSettings(SslProtocols.Tls11, false, new List<X509Certificate>(), targetHost)
                );

                TlsHandler.Trace("Test" + nameof(this.TlsRead1), "Register handler");
                var ch = new EmbeddedChannel(tlsHandler);
                var writeStrategy = new AsIsWriteStrategy();

                IByteBuffer readResultBuffer = Unpooled.Buffer(4 * 1024);

                var writeTasks = new List<Task>();
                var mediationStream = new MediationStream(
                    async output =>
                    {
                        TlsHandler.Trace("Test" + nameof(this.TlsRead1), "TestMediationStream.ReadFunc");
                        if (writeTasks.Count > 0)
                        {
                            await Task.WhenAll(writeTasks).WithTimeout(TimeSpan.FromSeconds(2));
                            writeTasks.Clear();
                        }

                        if (readResultBuffer.ReadableBytes < output.Count)
                        {
                            if (ch.Active)
                            {
                                var buffer = ch.ReadOutbound<IByteBuffer>();
                                if (buffer != null)
                                {
                                    if (buffer.IsReadable())
                                    {
                                        readResultBuffer.WriteBytes(buffer);
                                    }

                                    buffer.Release();
                                }
                            }
                        }

                        int read = Math.Min(output.Count, readResultBuffer.ReadableBytes);
                        readResultBuffer.ReadBytes(output.Array, output.Offset, read);
                        return read;
                    },
                    input =>
                    {
                        TlsHandler.Trace("Test" + nameof(this.TlsRead1), "TestMediationStream.WriteFunc");
                        Task task = executor.SubmitAsync(
                            () =>
                            {
                                TlsHandler.Trace("Test" + nameof(this.TlsRead1), "TestMediationStream.WriteFunc in executor thread");
                                return writeStrategy.WriteToChannelAsync(ch, input);
                            }).Unwrap();
                        writeTasks.Add(task);
                        return task;
                    },
                    () => ch.CloseAsync()
                );

                var serverSsl = new SslStream(mediationStream, true, (_1, _2, _3, _4) => true);
                TlsHandler.Trace("Test" + nameof(this.TlsRead1), "AuthenticateAsServerAsync");
                await Task.Run(() => serverSsl.AuthenticateAsServerAsync(tlsCertificate, false, SslProtocols.Tls11, false).WithTimeout(TimeSpan.FromSeconds(2)));
                writeTasks.Clear();
            }
            catch (Exception)
            {
                // while (TlsHandler.Events.TryDequeue(out string msg))
                // {
                //     this.Output.WriteLine(msg);
                // }

                throw;
            }
            finally
            {
                while (TlsHandler.Events.TryDequeue(out string msg))
                {
                    this.Output.WriteLine(msg);
                }
                await executor.ShutdownGracefullyAsync(TimeSpan.Zero, TimeSpan.Zero);
            }
        }


        [Theory]
        [MemberData(nameof(GetTlsReadTestData))]
        public async Task TlsRead(int[] frameLengths, bool isClient, IWriteStrategy writeStrategy, SslProtocols serverProtocol, SslProtocols clientProtocol)
        {
            while (TlsHandler.Events.TryDequeue(out _))
            {
            }

            
            this.Output.WriteLine($"frameLengths: {string.Join(", ", frameLengths)}");
            this.Output.WriteLine($"isClient: {isClient}");
            this.Output.WriteLine($"writeStrategy: {writeStrategy}");
            this.Output.WriteLine($"serverProtocol: {serverProtocol}");
            this.Output.WriteLine($"clientProtocol: {clientProtocol}");

            var executor = new SingleThreadEventExecutor("test executor", TimeSpan.FromMilliseconds(10));

            try
            {
                var writeTasks = new List<Task>();
                var pair = await SetupStreamAndChannelAsync(isClient, executor, writeStrategy, serverProtocol, clientProtocol, writeTasks).WithTimeout(TimeSpan.FromSeconds(10));
                EmbeddedChannel ch = pair.Item1;
                SslStream driverStream = pair.Item2;

                int randomSeed = Environment.TickCount;
                var random = new Random(randomSeed);
                IByteBuffer expectedBuffer = Unpooled.Buffer(16 * 1024);
                foreach (int len in frameLengths)
                {
                    var data = new byte[len];
                    random.NextBytes(data);
                    expectedBuffer.WriteBytes(data);
                    await driverStream.WriteAsync(data, 0, data.Length).WithTimeout(TimeSpan.FromSeconds(5));
                }
                await Task.WhenAll(writeTasks).WithTimeout(TimeSpan.FromSeconds(5));
                IByteBuffer finalReadBuffer = Unpooled.Buffer(16 * 1024);
                await ReadOutboundAsync(async () => ch.ReadInbound<IByteBuffer>(), expectedBuffer.ReadableBytes, finalReadBuffer, TestTimeout);
                bool isEqual = ByteBufferUtil.Equals(expectedBuffer, finalReadBuffer);
                if (!isEqual)
                {
                    Assert.True(isEqual, $"---Expected:\n{ByteBufferUtil.PrettyHexDump(expectedBuffer)}\n---Actual:\n{ByteBufferUtil.PrettyHexDump(finalReadBuffer)}");
                }
                driverStream.Dispose();
                Assert.False(ch.Finish());
            }
            catch (Exception)
            {
                while (TlsHandler.Events.TryDequeue(out string msg))
                {
                    this.Output.WriteLine(msg);
                }

                throw;
            }
            finally
            {
                await executor.ShutdownGracefullyAsync(TimeSpan.Zero, TimeSpan.Zero);
            }
        }

        public static IEnumerable<object[]> GetTlsWriteTestData()
        {
            var random = new Random(Environment.TickCount);
            var lengthVariations =
                new[]
                {
                    new[] { 1 },
                    new[] { 2, 8000, 300 },
                    new[] { 100, 0, 1000 },
                    new[] { 4 * 1024 - 10, 1, -1, 0, -1, 1 },
                    new[] { 0, 24000, 0, -1, 1000 },
                    new[] { 0, 4000, 0 },
                    new[] { 16 * 1024 - 100 },
                    Enumerable.Repeat(0, 30).Select(_ => random.Next(0, 10) < 2 ? -1 : random.Next(0, 17000)).ToArray()
                };
            var boolToggle = new[] { false, true };
            var protocols = new[]
            {
                Tuple.Create(SslProtocols.Tls, SslProtocols.Tls),
                Tuple.Create(SslProtocols.Tls11, SslProtocols.Tls11),
                Tuple.Create(SslProtocols.Tls12, SslProtocols.Tls12),
                Tuple.Create(SslProtocols.Tls12 | SslProtocols.Tls, SslProtocols.Tls12 | SslProtocols.Tls11),
                Tuple.Create(SslProtocols.Tls | SslProtocols.Tls12, SslProtocols.Tls | SslProtocols.Tls11)
            };

            return
                from frameLengths in lengthVariations
                from isClient in boolToggle
                from protocol in protocols
                select new object[] { frameLengths, isClient, protocol.Item1, protocol.Item2 };
        }

        [Theory]
        [MemberData(nameof(GetTlsWriteTestData))]
        public async Task TlsWrite(int[] frameLengths, bool isClient, SslProtocols serverProtocol, SslProtocols clientProtocol)
        {
            while (TlsHandler.Events.TryDequeue(out _))
            {
            }

            
            this.Output.WriteLine($"frameLengths: {string.Join(", ", frameLengths)}");
            this.Output.WriteLine($"isClient: {isClient}");
            this.Output.WriteLine($"serverProtocol: {serverProtocol}");
            this.Output.WriteLine($"clientProtocol: {clientProtocol}");

            var writeStrategy = new AsIsWriteStrategy();
            this.Output.WriteLine($"writeStrategy: {writeStrategy}");

            var executor = new SingleThreadEventExecutor("test executor", TimeSpan.FromMilliseconds(10));

            try
            {
                var writeTasks = new List<Task>();
                var pair = await SetupStreamAndChannelAsync(isClient, executor, writeStrategy, serverProtocol, clientProtocol, writeTasks);
                EmbeddedChannel ch = pair.Item1;
                SslStream driverStream = pair.Item2;

                int randomSeed = Environment.TickCount;
                var random = new Random(randomSeed);
                IByteBuffer expectedBuffer = Unpooled.Buffer(16 * 1024);
                foreach (IEnumerable<int> lengths in frameLengths.Split(x => x < 0))
                {
                    ch.WriteOutbound(lengths.Select(len =>
                    {
                        var data = new byte[len];
                        random.NextBytes(data);
                        expectedBuffer.WriteBytes(data);
                        return (object)Unpooled.WrappedBuffer(data);
                    }).ToArray());
                }

                IByteBuffer finalReadBuffer = Unpooled.Buffer(16 * 1024);
                var readBuffer = new byte[16 * 1024 * 10];
                await ReadOutboundAsync(
                    async () =>
                    {
                        int read = await driverStream.ReadAsync(readBuffer, 0, readBuffer.Length);
                        return Unpooled.WrappedBuffer(readBuffer, 0, read);
                    },
                    expectedBuffer.ReadableBytes, finalReadBuffer, TestTimeout);
                bool isEqual = ByteBufferUtil.Equals(expectedBuffer, finalReadBuffer);
                if (!isEqual)
                {
                    Assert.True(isEqual, $"---Expected:\n{ByteBufferUtil.PrettyHexDump(expectedBuffer)}\n---Actual:\n{ByteBufferUtil.PrettyHexDump(finalReadBuffer)}");
                }
                driverStream.Dispose();
                Assert.False(ch.Finish());
            }
            finally
            {
                await executor.ShutdownGracefullyAsync(TimeSpan.Zero, TimeSpan.Zero);
            }
        }

        static async Task<Tuple<EmbeddedChannel, SslStream>> SetupStreamAndChannelAsync(bool isClient, IEventExecutor executor, IWriteStrategy writeStrategy, SslProtocols serverProtocol, SslProtocols clientProtocol, List<Task> writeTasks)
        {
            X509Certificate2 tlsCertificate = TestResourceHelper.GetTestCertificate();
            string targetHost = tlsCertificate.GetNameInfo(X509NameType.DnsName, false);
            TlsHandler tlsHandler = isClient ?
                new TlsHandler(stream => new SslStream(stream, true, (sender, certificate, chain, errors) => true), new ClientTlsSettings(clientProtocol, false, new List<X509Certificate>(), targetHost)) :
                new TlsHandler(new ServerTlsSettings(tlsCertificate, false, false, serverProtocol));
            //var ch = new EmbeddedChannel(new LoggingHandler("BEFORE"), tlsHandler, new LoggingHandler("AFTER"));
            var ch = new EmbeddedChannel(tlsHandler);

            IByteBuffer readResultBuffer = Unpooled.Buffer(4 * 1024);
            Func<ArraySegment<byte>, Task<int>> readDataFunc = async output =>
            {
                TlsHandler.Trace("Test" + nameof(SetupStreamAndChannelAsync), "readDataFunc");
                if (writeTasks.Count > 0)
                {
                    await Task.WhenAll(writeTasks).WithTimeout(TestTimeout);
                    writeTasks.Clear();
                }

                if (readResultBuffer.ReadableBytes < output.Count)
                {
                    if (ch.Active)
                        await ReadOutboundAsync(async () => ch.ReadOutbound<IByteBuffer>(), output.Count - readResultBuffer.ReadableBytes, readResultBuffer, TestTimeout, readResultBuffer.ReadableBytes != 0 ? 0 : 1);
                }
                int read = Math.Min(output.Count, readResultBuffer.ReadableBytes);
                readResultBuffer.ReadBytes(output.Array, output.Offset, read);
                return read;
            };
            var mediationStream = new MediationStream(readDataFunc, input =>
            {
                TlsHandler.Trace("Test" + nameof(SetupStreamAndChannelAsync), "writeDataFunc");
                Task task = executor.SubmitAsync(() => writeStrategy.WriteToChannelAsync(ch, input)).Unwrap();
                writeTasks.Add(task);
                return task;
            }, () =>
            {
                ch.CloseAsync();
            });

            var driverStream = new SslStream(mediationStream, true, (_1, _2, _3, _4) => true);
            if (isClient)
            {
                TlsHandler.Trace("Test" + nameof(SetupStreamAndChannelAsync), "AuthenticateAsServerAsync");
                await Task.Run(() => driverStream.AuthenticateAsServerAsync(tlsCertificate, false, serverProtocol, false)).WithTimeout(TimeSpan.FromSeconds(5));
            }
            else
            {
                TlsHandler.Trace("Test" + nameof(SetupStreamAndChannelAsync), "AuthenticateAsClientAsync");
                await Task.Run(() => driverStream.AuthenticateAsClientAsync(targetHost, null, clientProtocol, false)).WithTimeout(TimeSpan.FromSeconds(5));
            }
            writeTasks.Clear();
            
            

            return Tuple.Create(ch, driverStream);
        }

        static Task ReadOutboundAsync(Func<Task<IByteBuffer>> readFunc, int expectedBytes, IByteBuffer result, TimeSpan timeout, int minBytes = -1)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            int remaining = expectedBytes;
            if (minBytes < 0) minBytes = expectedBytes;
            if (minBytes > expectedBytes) throw new ArgumentOutOfRangeException("minBytes can not greater than expectedBytes");
            return AssertEx.EventuallyAsync(
                async () =>
                {
                    TimeSpan readTimeout = timeout - stopwatch.Elapsed;
                    if (readTimeout <= TimeSpan.Zero)
                    {
                        return false;
                    }

                    IByteBuffer output;
                    while(true)
                    {
                        output = await readFunc().WithTimeout(readTimeout);//inbound ? ch.ReadInbound<IByteBuffer>() : ch.ReadOutbound<IByteBuffer>();
                        if (output == null)
                            break;

                        if (!output.IsReadable())
                        {
                            output.Release();
                            return true;
                        }

                        remaining -= output.ReadableBytes;
                        minBytes -= output.ReadableBytes;
                        result.WriteBytes(output);
                        output.Release();

                        if (remaining <= 0)
                            return true;
                    }
                    return minBytes <= 0;
                },
                TimeSpan.FromMilliseconds(10),
                timeout);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void NoAutoReadHandshakeProgresses(bool dropChannelActive)
        {
            var readHandler = new ReadRegisterHandler();
            var ch = new EmbeddedChannel(EmbeddedChannelId.Instance, false, false,
               readHandler,
               TlsHandler.Client("dotnetty.com"),
               new ActivatingHandler(dropChannelActive)
           );

           ch.Configuration.AutoRead = false;
           ch.Register();
           Assert.False(ch.Configuration.AutoRead);
           Assert.True(ch.WriteOutbound(Unpooled.Empty));
           Assert.True(readHandler.ReadIssued);
           ch.CloseAsync();
        }

        class ReadRegisterHandler : ChannelHandlerAdapter
        {
            public bool ReadIssued { get; private set; }

            public override void Read(IChannelHandlerContext context)
            {
                this.ReadIssued = true;
                base.Read(context);
            }
        }

        class ActivatingHandler : ChannelHandlerAdapter
        {
            bool dropChannelActive;

            public ActivatingHandler(bool dropChannelActive)
            {
                this.dropChannelActive = dropChannelActive;
            }

            public override void ChannelActive(IChannelHandlerContext context)
            {
                if (!dropChannelActive)
                {
                    context.FireChannelActive();
                }
            }
        }
    }
}
