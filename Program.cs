using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FtpRunner
{
    class Program
    {
        static bool _verbose = false;

        static async Task Main(string[] args)
        {
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            try
            {
                if (args.Length != 0)
                {
                    _verbose = true;
                    foreach (var arg in args)
                    {
                        RunFtpForStamp(arg).Wait();
                    }
                    return;
                }

                _verbose = Environment.GetEnvironmentVariable("FTPRUNNER_VERBOSE") == "1";

                while (true)
                {
                    await RunFtpRunner();
                }
            }
            catch (Exception ex)
            {
                Logger.Instance.AppendLine(ex);
            }
        }

        static ConcurrentDictionary<string, int> _maxStampIndexes = new ConcurrentDictionary<string, int>();

        static string[] _stamps = new[]
        {
            "waws-prod-euapdm1-505",
            "waws-prod-msftbay-901",
            "waws-prod-msftblu-901",
            "waws-prod-msftdb3-901",
            "waws-prod-msfthk1-901",
            "waws-prod-am2-001",
            "waws-prod-auh-001",
            "waws-prod-bay-001",
            "waws-prod-ber-001",
            "waws-prod-blu-001",
            "waws-prod-bm1-001",
            "waws-prod-bn1-001",
            "waws-prod-brse-001",
            "waws-prod-cbr20-001",
            "waws-prod-cbr21-001",
            "waws-prod-ch1-001",
            "waws-prod-chw-001",
            "waws-prod-cpt20-001",
            "waws-prod-cq1-001",
            "waws-prod-cw1-001",
            "waws-prod-cy4-001",
            "waws-prod-db3-001",
            "waws-prod-dm1-001",
            "waws-prod-dxb-001",
            "waws-prod-euapbn1-001",
            "waws-prod-euapdm1-001",
            "waws-prod-fra-001",
            "waws-prod-hk1-001",
            "waws-prod-jinc-001",
            "waws-prod-jinw-001",
            "waws-prod-jnb21-001",
            "waws-prod-kw1-001",
            "waws-prod-ln1-001",
            "waws-prod-ma1-001",
            "waws-prod-ml1-001",
            "waws-prod-mrs-001",
            "waws-prod-mwh-001",
            "waws-prod-os1-001",
            "waws-prod-osl-001",
            "waws-prod-par-001",
            "waws-prod-plc-001",
            "waws-prod-pn1-001",
            "waws-prod-ps1-001",
            "waws-prod-qac-001",
            "waws-prod-se1-001",
            "waws-prod-sec-001",
            "waws-prod-ses-001",
            "waws-prod-sg1-001",
            "waws-prod-sn1-001",
            "waws-prod-svg-001",
            "waws-prod-sy3-001",
            "waws-prod-ty1-001",
            "waws-prod-usw3-001",
            "waws-prod-xyz-001",
            "waws-prod-yq1-001",
            "waws-prod-yt1-001",
            "waws-prod-zrh-001",
        };

        static async Task RunFtpRunner()
        {
            var semaphore = new SemaphoreSlim(initialCount: 5);
            foreach (var stamp0 in _stamps)
            {
                await RunFtpForStamp0(stamp0, semaphore);
            }
        }

        static async Task RunFtpForStamp0(string stamp0, SemaphoreSlim semaphore)
        {
            var parts = stamp0.Split('-');
            var index = int.Parse(parts[3]);
            int maxIndex;
            if (!_maxStampIndexes.TryGetValue(stamp0, out maxIndex))
            {
                maxIndex = -1;
            }

            while (true)
            {
                var stamp = string.Format("{0}-{1}-{2}-{3:000}", parts[0], parts[1], parts[2], index);

                if (index > maxIndex)
                {
                    if (await CheckDns(stamp))
                    {
                        maxIndex = index;

                        _maxStampIndexes.AddOrUpdate(stamp0, maxIndex, (_, __) => maxIndex);
                    }
                    else if (index > (maxIndex + 4))
                    {
                        break;
                    }
                }

                var acquired = await semaphore.WaitAsync(TimeSpan.FromMinutes(1));
                if (!acquired)
                {
                    Environment.FailFast($"FtpRunner: timeout waiting for semaphore {stamp}");
                    return;
                }

                _ = RunFtpForStamp(stamp, semaphore);

                index = index + 2;
            }
        }

        static async Task RunFtpForStamp(string stampName, SemaphoreSlim semaphore)
        {
            try
            {
                await RunFtpForStamp(stampName);
            }
            catch (Exception ex)
            {
                Logger.Instance.AppendLine($"{stampName} {ex.Message}");
            }
            finally
            {
                semaphore.Release();
            }
        }

        static async Task RunFtpForStamp(string stampName)
        {
            try
            {
                var userName = Environment.GetEnvironmentVariable("FTP_USERNAME");
                var password = Environment.GetEnvironmentVariable("FTP_PASSWORD");

                var siteName = userName.StartsWith("$") ? userName.Substring(1) : stampName.Replace("waws-prod-", "antares-prod-");
                var ftpHostname = $"{stampName}.ftp.azurewebsites.windows.net";
                var drips = Dns.GetHostAddresses(ftpHostname);

                foreach (var enableSsl in new[] { true }) // , true })
                {
                    await PingFtp(ftpHostname, $"ftp://{ftpHostname}/site/wwwroot", siteName, userName, password, enableSsl);
                    foreach (var drip in drips)
                    {
                        await PingFtp(ftpHostname, $"ftp://{drip}/site/wwwroot", siteName, userName, password, enableSsl);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Instance.AppendLine($"{stampName} {ex.Message}");
            }
        }

        static async Task PingFtp(string hostName, string url, string siteName, string userName, string password, bool EnableSsl)
        {
            var start = DateTime.UtcNow;
            var strb = new StringBuilder();
            strb.Append($"Connecting to {siteName}, {url} - ");

            try
            {
                //FtpWebRequest request = (FtpWebRequest)WebRequest.Create(url);
                //request.Method = WebRequestMethods.Ftp.ListDirectory;
                //request.Credentials = new NetworkCredential(String.Format("{0}\\{1}", siteName, userName), password);
                //if (EnableSsl)
                //{
                //    // ExplicitSSLFtps
                //    // Explicit do control over 21 and data securedly over data channel
                //    request.EnableSsl = EnableSsl;
                //}

                //using (WebResponse response = await request.GetResponseAsync())
                //{
                //    strb.AppendFormat("connected ({0}ms) ", (int)(DateTime.UtcNow - start).TotalMilliseconds);
                //    using (var streamReader = new StreamReader(response.GetResponseStream()))
                //    {
                //        while (!streamReader.EndOfStream)
                //        {
                //            var line = await streamReader.ReadLineAsync();
                //            strb.Append('.');
                //        }
                //    }
                //}

                await ImplicitSSLFtps(hostName, new Uri(url).Host, siteName, userName, password, strb);
            }
            catch (Exception ex)
            {
                strb.AppendLine(ex.Message);
                if (!_verbose) Console.Write($"{siteName}({url}).");
            }

            //  Logger.Instance.AppendLine(strb);
            if (!_verbose) Console.Write(".");
            else
            {
                lock(typeof(Console))
                {
                    Console.WriteLine(strb);
                }
            }
        }

        static async Task<bool> CheckDns(string stamp)
        {
            try
            {
                var entry = await Dns.GetHostEntryAsync(string.Format("{0}.vip.azurewebsites.windows.net", stamp));
                if (string.IsNullOrEmpty(entry.HostName))
                {
                    throw new InvalidOperationException("entry.HostName is null or empty!");
                }
                if (!entry.HostName.StartsWith(stamp, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException($"Invalid entry.HostName {entry.HostName}");
                }
                if (!entry.HostName.EndsWith(".cloudapp.net", StringComparison.OrdinalIgnoreCase)
                    && !entry.HostName.EndsWith(".cloudapp.azure.com", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException($"Invalid entry.HostName {entry.HostName}");
                }

                return true;
            }
            catch (Exception ex)
            {
                Logger.Instance.AppendLine($"{stamp} {ex.Message}");
                return false;
            }
        }

        static void ExplicitSSLFtps(string hostName, string siteName, string userName, string password)
        {
            FtpWebRequest request = (FtpWebRequest)WebRequest.Create($"ftp://{hostName}/site/wwwroot");
            request.Method = WebRequestMethods.Ftp.ListDirectory;
            request.Credentials = new NetworkCredential($"{siteName}\\{userName}", password);
            request.EnableSsl = true; // Here you enabled request to use ssl instead of clear text
            WebResponse response = request.GetResponse();
            using (var streamReader = new StreamReader(response.GetResponseStream()))
            {
                Console.WriteLine("connected");
                Console.WriteLine(streamReader.ReadToEnd());
            }
        }

        static async Task ImplicitSSLFtps(string hostName, string ipAddress, string siteName, string userName, string password, StringBuilder strb)
        {
            //RemoteCertificateValidationCallback certValidator = delegate
            //{
            //    Console.WriteLine("RemoteCertificateValidationCallback called");
            //    return true;
            //};

            // Open a connection to the server over port 990
            // (default port for FTP over implicit SSL)
            using (TcpClient client = new TcpClient(ipAddress, 990))
            using (SslStream sslStream = new SslStream(client.GetStream(), true))
            {
                var buf = new byte[64];

                // Start SSL/TLS Handshake
                await sslStream.AuthenticateAsClientAsync(hostName);

                var read = await sslStream.ReadAsync(buf, 0, buf.Length);
                //Console.WriteLine($"ImplicitSSLFtps connected {read} {Encoding.UTF8.GetString(buf, 0, read)}");

                // Setup a delegate for writing FTP commands to the SSL stream
                var WriteCommandAsync = new Func<string, Task>(async command =>
                {
                    byte[] commandBytes =
                    Encoding.ASCII.GetBytes(command + Environment.NewLine);
                    await sslStream.WriteAsync(commandBytes, 0, commandBytes.Length);
                    await sslStream.FlushAsync();
                });

                // Write raw FTP commands to the SSL stream
                await WriteCommandAsync($"USER {siteName}\\{userName}");
                read = await sslStream.ReadAsync(buf, 0, buf.Length);
                //Console.WriteLine($"ImplicitSSLFtps connected {read} {Encoding.UTF8.GetString(buf, 0, read)}");
                await WriteCommandAsync($"PASS {password}");
                read = await sslStream.ReadAsync(buf, 0, buf.Length);
                //User logged in.
                //Console.WriteLine($"Connect {hostName}({ipAddress}) {read} {Encoding.UTF8.GetString(buf, 0, read)}");
                strb.Append($"{read} bytes read '{Encoding.UTF8.GetString(buf, 0, read)}'");

                // Connect to data port to download the file
            }
        }
    }
}
