using System;
using System.IO;
using System.Text;
using System.Net;
using System.Threading.Tasks;
using System.Diagnostics;
using Cloudmersive.APIClient.NET.VirusScan.Api;
using Cloudmersive.APIClient.NET.VirusScan.Client;
using Cloudmersive.APIClient.NET.VirusScan.Model;

namespace viruscanapi
{
    class Program
    {
        public static HttpListener listener;
        public static string url = "http://localhost:8000/";
        public static string tempFilePath = "C:\\temp\\data";
        public static string apiKey = "7ccc4630-8aca-416d-8264-9b8dc4dc5290";
        public static int pageViews = 0;
        public static int requestCount = 0;
        public static string pageData =
            "<!DOCTYPE>" +
            "<html>" +
            "  <head>" +
            "    <title>Virus Scanner using Cloudmersive virus scan API</title>" +
            "  </head>" +
            "  <body>" +
            "<div>To check for virus in the file, upload it below</div> " +
            "    <form method=\"post\" action=\"scanner\" enctype=\"multipart/form-data\">" +
            "<input type=\"file\" name=\"fileToScan\">" +
            "      <input type=\"submit\" value=\"Scan\" {1}>" +
            "    </form>" +
            "  </body>" +
            "</html>";
        public static async Task HandleIncomingConnections()
        {
            bool runServer = true;

            while (runServer)
            {
             
                HttpListenerContext ctx = await listener.GetContextAsync();

                HttpListenerRequest req = ctx.Request;
                HttpListenerResponse resp = ctx.Response;
                Console.WriteLine("Request #: {0}", ++requestCount);
                Console.WriteLine(req.Url.ToString());
                Console.WriteLine(req.HttpMethod);
                Console.WriteLine(req.UserHostName);
                Console.WriteLine(req.UserAgent);
                Console.WriteLine();

                if ((req.HttpMethod == "POST") && (req.Url.AbsolutePath == "/scanner"))
                {
                    Console.WriteLine("scan Api requested");


                    SaveFile(ctx.Request.ContentEncoding, GetBoundary(ctx.Request.ContentType), ctx.Request.InputStream);



                    Configuration.Default.AddApiKey("Apikey", apiKey);
                    var apiInstance = new ScanApi();
                    var inputFile = new System.IO.FileStream(tempFilePath, System.IO.FileMode.Open); 
                    try
                    {
                      
                        VirusScanResult result = apiInstance.ScanFile(inputFile);
                        Debug.WriteLine(result);

                        if ((Boolean)result.CleanResult)
                        {
                           pageData =
            "<!DOCTYPE>" +
            "<html>" +
            "  <head>" +
            "    <title>Virus Scanner using Cloudmersive virus scan API</title>" +
            "  </head>" +
            "  <body>" +
            "<div>There is no virus in the file. To check for another file, upload it below</div> " +
            "    <p>Page Views: {0}</p>" +
            "    <form method=\"post\" action=\"scanner\" enctype=\"multipart/form-data\">" +
            "<input type=\"file\" name=\"fileToScan\">" +
            "      <input type=\"submit\" value=\"Scan\" {1}>" +
            "    </form>" +
            "  </body>" +
            "</html>";
                        }
                        else
                        {
                           pageData =
            "<!DOCTYPE>" +
            "<html>" +
            "  <head>" +
            "    <title>Virus Scanner using Cloudmersive virus scan API</title>" +
            "  </head>" +
            "  <body>" +
            "<div>There is virus in the file. To check for another file, upload it below</div> " +
            "    <p>Page Views: {0}</p>" +
            "    <form method=\"post\" action=\"scanner\" enctype=\"multipart/form-data\">" +
            "<input type=\"file\" name=\"fileToScan\">" +
            "      <input type=\"submit\" value=\"Scan\" {1}>" +
            "    </form>" +
            "  </body>" +
            "</html>";
                        }

                        inputFile.Close();

                    }
                    catch (Exception e)
                    {
                        inputFile.Close();
                        Debug.Print("Exception when calling ScanApi.ScanFile: " + e.Message);
                    }
                    runServer = true;
                    
                }
                string disableSubmit = !runServer ? "disabled" : "";
                byte[] data = Encoding.UTF8.GetBytes(String.Format(pageData, pageViews, disableSubmit));
                resp.ContentType = "text/html";
                resp.ContentEncoding = Encoding.UTF8;
                resp.ContentLength64 = data.LongLength;
                await resp.OutputStream.WriteAsync(data, 0, data.Length);
                resp.Close();
            }
        }
        public static void Main(string[] args)
        {
          
            listener = new HttpListener();
            listener.Prefixes.Add(url);
            listener.Start();
            Console.WriteLine("Listening for connections on {0}", url);

           
            Task listenTask = HandleIncomingConnections();
            listenTask.GetAwaiter().GetResult();

            
            listener.Close();
        }
        private static String GetBoundary(String ctype)
        {
            return "--" + ctype.Split(';')[1].Split('=')[1];
        }

        private static void SaveFile(Encoding enc, String boundary, Stream input)
        {
            Byte[] boundaryBytes = enc.GetBytes(boundary);
            Int32 boundaryLen = boundaryBytes.Length;

            using (FileStream output = new FileStream(tempFilePath, FileMode.Create, FileAccess.Write))
            {
                Byte[] buffer = new Byte[1024];
                Int32 len = input.Read(buffer, 0, 1024);
                Int32 startPos = -1;

           
                while (true)
                {
                    if (len == 0)
                    {
                        throw new Exception("Start Boundaray Not Found");
                    }

                    startPos = IndexOf(buffer, len, boundaryBytes);
                    if (startPos >= 0)
                    {
                        break;
                    }
                    else
                    {
                        Array.Copy(buffer, len - boundaryLen, buffer, 0, boundaryLen);
                        len = input.Read(buffer, boundaryLen, 1024 - boundaryLen);
                    }
                }
                for (Int32 i = 0; i < 4; i++)
                {
                    while (true)
                    {
                        if (len == 0)
                        {
                            throw new Exception("Preamble not Found.");
                        }

                        startPos = Array.IndexOf(buffer, enc.GetBytes("\n")[0], startPos);
                        if (startPos >= 0)
                        {
                            startPos++;
                            break;
                        }
                        else
                        {
                            len = input.Read(buffer, 0, 1024);
                        }
                    }
                }

                Array.Copy(buffer, startPos, buffer, 0, len - startPos);
                len = len - startPos;

                while (true)
                {
                    Int32 endPos = IndexOf(buffer, len, boundaryBytes);
                    if (endPos >= 0)
                    {
                        if (endPos > 0) output.Write(buffer, 0, endPos - 2);
                        break;
                    }
                    else if (len <= boundaryLen)
                    {
                        throw new Exception("End Boundaray Not Found");
                    }
                    else
                    {
                        output.Write(buffer, 0, len - boundaryLen);
                        Array.Copy(buffer, len - boundaryLen, buffer, 0, boundaryLen);
                        len = input.Read(buffer, boundaryLen, 1024 - boundaryLen) + boundaryLen;
                    }
                }
            }
        }

        private static Int32 IndexOf(Byte[] buffer, Int32 len, Byte[] boundaryBytes)
        {
            for (Int32 i = 0; i <= len - boundaryBytes.Length; i++)
            {
                Boolean match = true;
                for (Int32 j = 0; j < boundaryBytes.Length && match; j++)
                {
                    match = buffer[i + j] == boundaryBytes[j];
                }

                if (match)
                {
                    return i;
                }
            }

            return -1;
        }
    
    
    }
}
