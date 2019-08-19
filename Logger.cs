using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace FtpRunner
{
    class Logger
    {
        private const int MaxFiles = 5;
        private const int MaxLines = 500;
        private int _lines = 0;
        private string _fileName = null;
        private static Lazy<int> PID = new Lazy<int>(() => Process.GetCurrentProcess().Id);

        public readonly static Logger Instance = new Logger();

        Logger()
        {
            LogPath = Path.Combine(Environment.GetEnvironmentVariable("TEMP"), Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().Location));
            Directory.CreateDirectory(LogPath);
        }

        public string LogPath { get; set; }

        public void AppendLine(object obj)
        {
            AppendLine("{0}", obj);
        }

        public void AppendLine(string format, params object[] args)
        {
            var strb = new StringBuilder();
            strb.AppendFormat("{0:s} - ", DateTime.UtcNow);
            strb.AppendFormat(format, args);
            lock (typeof(Logger))
            {
                var filePath = GetLogFile();
                File.AppendAllLines(filePath, new[] { strb.ToString() });
                ++_lines;

                Console.WriteLine(strb);
            }
        }

        private string GetLogFile()
        {
            if (_fileName == null || _lines > MaxLines)
            {
                PurgeOldFile();
                _fileName = Path.Combine(LogPath, string.Format("Job_{0}_{1}.txt", DateTime.UtcNow.ToString("yyyy-MM-dd_HH-mm-ss"), PID.Value));
                _lines = 0;
            }

            return _fileName;
        }

        private void PurgeOldFile()
        {
            var files = Directory.GetFiles(LogPath, "Job_*.txt", SearchOption.TopDirectoryOnly)
                .OrderBy(f => f)
                .ToList();
            var toRemove = files.Count - MaxFiles;
            if (toRemove > 0)
            {
                foreach(var file in files.Take(toRemove))
                {
                    File.Delete(file);
                }
            }
        }
    }
}
