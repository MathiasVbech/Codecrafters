using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.IO;
using System.IO.Compression;

// You can use print statements as follows for debugging, they'll be visible when running tests.
Console.WriteLine("Logs from your program will appear here!");

// Parse command line arguments to get directory path
string directoryPath = ParseDirectoryArgument(args);
Console.WriteLine($"Files directory: {directoryPath}");

// Create a TCP listener on port 4221
TcpListener server = new TcpListener(IPAddress.Any, 4221);
server.Start();
Console.WriteLine("Server started on port 4221. Waiting for connections...");

while (true)
{
    try
    {
        // Accept incoming client connection
        Socket clientSocket = server.AcceptSocket();
        Console.WriteLine($"Client connected from {clientSocket.RemoteEndPoint}");
        
        // Handle the client connection in a separate thread, passing the directory path
        Thread clientThread = new Thread(() => HandleClient(clientSocket, directoryPath));
        clientThread.Start();
    }
    catch (Exception e)
    {
        Console.WriteLine($"Error in main thread: {e.Message}");
    }
}

// Parse the --directory command line argument
static string ParseDirectoryArgument(string[] args)
{
    for (int i = 0; i < args.Length - 1; i++)
    {
        if (args[i] == "--directory")
        {
            return args[i + 1];
        }
    }
    
    // Default to current directory if no directory is specified
    return Directory.GetCurrentDirectory();
}

// Method to handle a client connection
static void HandleClient(Socket clientSocket, string directoryPath)
{
    try
    {
        // Buffer to store received data
        byte[] buffer = new byte[4096]; // Increased buffer size for larger requests
        int bytesRead = clientSocket.Receive(buffer);
        string request = Encoding.ASCII.GetString(buffer, 0, bytesRead);
        
        Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} received request from {clientSocket.RemoteEndPoint}");
        
        // Extract HTTP method and URL path from the request
        string httpMethod = ExtractHttpMethod(request);
        string urlPath = ExtractUrlPath(request);
        Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - Method: {httpMethod}, URL path: {urlPath}");
        
        // Check for Accept-Encoding header and determine if gzip is supported
        string acceptEncoding = ExtractHeader(request, "Accept-Encoding");
        bool clientSupportsGzip = false;
        
        // Parse the Accept-Encoding header to check for gzip
        if (!string.IsNullOrEmpty(acceptEncoding))
        {
            // Split by comma to get individual encodings
            string[] encodings = acceptEncoding.Split(',');
            
            // Check if any of the encodings is gzip (trimming whitespace)
            foreach (string encoding in encodings)
            {
                if (encoding.Trim().Equals("gzip", StringComparison.OrdinalIgnoreCase))
                {
                    clientSupportsGzip = true;
                    break;
                }
            }
        }
        
        Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - Accept-Encoding: {acceptEncoding}, Supports gzip: {clientSupportsGzip}");
        
        // Prepare HTTP response based on the URL path and method
        string textResponse = null;
        byte[] fileResponse = null;
        
        // Check if the URL is a file request
        Match fileMatch = Regex.Match(urlPath, @"^/files/(.+)$");
        if (fileMatch.Success)
        {
            string filename = fileMatch.Groups[1].Value;
            string filePath = Path.Combine(directoryPath, filename);
            
            if (httpMethod == "GET")
            {
                if (File.Exists(filePath))
                {
                    // Read the file content
                    byte[] fileContent = File.ReadAllBytes(filePath);
                    
                    byte[] responseBody;
                    
                    // Create the response headers
                    StringBuilder headers = new StringBuilder();
                    headers.Append("HTTP/1.1 200 OK\r\n");
                    headers.Append("Content-Type: application/octet-stream\r\n");
                    
                    // If client supports gzip, compress the response
                    if (clientSupportsGzip)
                    {
                        // Add Content-Encoding header for gzip
                        headers.Append("Content-Encoding: gzip\r\n");
                        
                        // Compress the file content
                        responseBody = CompressWithGzip(fileContent);
                    }
                    else
                    {
                        // Use uncompressed response
                        responseBody = fileContent;
                    }
                    
                    // Add Content-Length header
                    headers.Append($"Content-Length: {responseBody.Length}\r\n\r\n");
                    
                    byte[] headerBytes = Encoding.ASCII.GetBytes(headers.ToString());
                    
                    // Combine headers and file content
                    fileResponse = new byte[headerBytes.Length + responseBody.Length];
                    Buffer.BlockCopy(headerBytes, 0, fileResponse, 0, headerBytes.Length);
                    Buffer.BlockCopy(responseBody, 0, fileResponse, headerBytes.Length, responseBody.Length);
                    
                    Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - Sending file: {filename}, size: {fileContent.Length} bytes");
                }
                else
                {
                    textResponse = "HTTP/1.1 404 Not Found\r\n\r\n";
                    Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - File not found: {filename}");
                }
            }
            else if (httpMethod == "POST")
            {
                // Extract content length from request
                int contentLength = ExtractContentLength(request);
                
                if (contentLength > 0)
                {
                    // Extract request body
                    string requestBody = ExtractRequestBody(request);
                    if (requestBody != null)
                    {
                        // Ensure directory exists
                        Directory.CreateDirectory(Path.GetDirectoryName(filePath));
                        
                        // Write request body to file
                        File.WriteAllText(filePath, requestBody);
                        
                        textResponse = "HTTP/1.1 201 Created\r\n\r\n";
                        Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - Created file: {filename}");
                    }
                    else
                    {
                        textResponse = "HTTP/1.1 400 Bad Request\r\n\r\n";
                        Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - Bad request: missing body");
                    }
                }
                else
                {
                    textResponse = "HTTP/1.1 400 Bad Request\r\n\r\n";
                    Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - Bad request: Content-Length missing or invalid");
                }
            }
            else
            {
                textResponse = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
                Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - Method not allowed: {httpMethod}");
            }
        }
        else if (urlPath == "/user-agent")
        {
            // Extract User-Agent header from the request
            string userAgent = ExtractHeader(request, "User-Agent");
            
            byte[] responseBody;
            
            // Create the response headers
            StringBuilder responseBuilder = new StringBuilder();
            responseBuilder.Append("HTTP/1.1 200 OK\r\n");
            responseBuilder.Append("Content-Type: text/plain\r\n");
            
            // If client supports gzip, compress the response
            if (clientSupportsGzip)
            {
                // Add Content-Encoding header for gzip
                responseBuilder.Append("Content-Encoding: gzip\r\n");
                
                // Compress the user agent string
                byte[] uncompressedBytes = Encoding.UTF8.GetBytes(userAgent);
                responseBody = CompressWithGzip(uncompressedBytes);
            }
            else
            {
                // Use uncompressed response
                responseBody = Encoding.UTF8.GetBytes(userAgent);
            }
            
            // Add Content-Length header
            responseBuilder.Append($"Content-Length: {responseBody.Length}\r\n\r\n");
            
            // Convert the headers to bytes
            byte[] headerBytes = Encoding.ASCII.GetBytes(responseBuilder.ToString());
            
            // Combine headers and body
            fileResponse = new byte[headerBytes.Length + responseBody.Length];
            Buffer.BlockCopy(headerBytes, 0, fileResponse, 0, headerBytes.Length);
            Buffer.BlockCopy(responseBody, 0, fileResponse, headerBytes.Length, responseBody.Length);
            Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - Sending user-agent response");
        }
        // Check if the URL matches the echo pattern
        else if (urlPath.StartsWith("/echo/"))
        {
            // Get the string from the URL (everything after /echo/)
            string echoString = urlPath.Substring("/echo/".Length);
            
            byte[] responseBody;
            
            // Create the response headers
            StringBuilder responseBuilder = new StringBuilder();
            responseBuilder.Append("HTTP/1.1 200 OK\r\n");
            responseBuilder.Append("Content-Type: text/plain\r\n");
            
            // If client supports gzip, compress the response
            if (clientSupportsGzip)
            {
                // Add Content-Encoding header for gzip
                responseBuilder.Append("Content-Encoding: gzip\r\n");
                
                // Compress the echo string
                byte[] uncompressedBytes = Encoding.UTF8.GetBytes(echoString);
                responseBody = CompressWithGzip(uncompressedBytes);
            }
            else
            {
                // Use uncompressed response
                responseBody = Encoding.UTF8.GetBytes(echoString);
            }
            
            // Add Content-Length header
            responseBuilder.Append($"Content-Length: {responseBody.Length}\r\n\r\n");
            
            // Convert the headers to bytes
            byte[] headerBytes = Encoding.ASCII.GetBytes(responseBuilder.ToString());
            
            // Combine headers and body
            fileResponse = new byte[headerBytes.Length + responseBody.Length];
            Buffer.BlockCopy(headerBytes, 0, fileResponse, 0, headerBytes.Length);
            Buffer.BlockCopy(responseBody, 0, fileResponse, headerBytes.Length, responseBody.Length);
            Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - Sending echo response");
        }
        else if (urlPath == "/")
        {
            textResponse = "HTTP/1.1 200 OK\r\n\r\n";
            Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - Sending 200 OK response");
        }
        else
        {
            textResponse = "HTTP/1.1 404 Not Found\r\n\r\n";
            Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - Sending 404 Not Found response");
        }
        
        // Send the response to the client
        if (fileResponse != null)
        {
            clientSocket.Send(fileResponse);
        }
        else
        {
            byte[] responseBytes = Encoding.UTF8.GetBytes(textResponse);
            clientSocket.Send(responseBytes);
        }
        
        // Close the connection
        clientSocket.Close();
        Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} - Connection closed");
    }
    catch (Exception e)
    {
        Console.WriteLine($"Error in client handler thread: {e.Message}");
        try
        {
            clientSocket.Close();
        }
        catch
        {
            // Ignore errors when closing the socket
        }
    }
}

// Helper method to extract the HTTP method from an HTTP request
static string ExtractHttpMethod(string request)
{
    // Check if the request is empty
    if (string.IsNullOrEmpty(request))
    {
        return "GET"; // Default to GET if no method is specified
    }
    
    // Split the request by CRLF to get the request line
    string[] lines = request.Split(new[] { "\r\n" }, StringSplitOptions.None);
    
    // Check if there are any lines
    if (lines.Length == 0)
    {
        return "GET";
    }
    
    // Get the request line (first line)
    string requestLine = lines[0];
    
    // Split the request line by space to get the method, path, and HTTP version
    string[] parts = requestLine.Split(' ');
    
    // Check if the request line has any parts
    if (parts.Length == 0)
    {
        return "GET";
    }
    
    // Return the HTTP method (first part of the request line)
    return parts[0];
}

// Helper method to extract the URL path from an HTTP request
static string ExtractUrlPath(string request)
{
    // Check if the request is empty
    if (string.IsNullOrEmpty(request))
    {
        return "/";
    }
    
    // Split the request by CRLF to get the request line
    string[] lines = request.Split(new[] { "\r\n" }, StringSplitOptions.None);
    
    // Check if there are any lines
    if (lines.Length == 0)
    {
        return "/";
    }
    
    // Get the request line (first line)
    string requestLine = lines[0];
    
    // Split the request line by space to get the method, path, and HTTP version
    string[] parts = requestLine.Split(' ');
    
    // Check if the request line has at least 2 parts (method and path)
    if (parts.Length < 2)
    {
        return "/";
    }
    
    // Return the URL path (second part of the request line)
    return parts[1];
}

// Helper method to extract a specific header from the HTTP request
static string ExtractHeader(string request, string headerName)
{
    // Check if the request is empty
    if (string.IsNullOrEmpty(request))
    {
        return string.Empty;
    }
    
    // Create the regex pattern to match the header
    string pattern = $@"{headerName}: (.+?)\r\n";
    
    // Find the header in the request
    Match match = Regex.Match(request, pattern);
    
    // If found, return the header value, otherwise return empty string
    if (match.Success && match.Groups.Count > 1)
    {
        return match.Groups[1].Value;
    }
    
    return string.Empty;
}

// Helper method to extract Content-Length header value from the HTTP request
static int ExtractContentLength(string request)
{
    string contentLengthStr = ExtractHeader(request, "Content-Length");
    if (!string.IsNullOrEmpty(contentLengthStr) && int.TryParse(contentLengthStr, out int contentLength))
    {
        return contentLength;
    }
    
    return 0;
}

// Helper method to extract the request body from an HTTP request
static string ExtractRequestBody(string request)
{
    // Check if the request is empty
    if (string.IsNullOrEmpty(request))
    {
        return null;
    }
    
    // The request body starts after the double CRLF
    int bodyStart = request.IndexOf("\r\n\r\n");
    if (bodyStart != -1)
    {
        bodyStart += 4; // Move past the double CRLF
        
        // Return the request body
        if (bodyStart < request.Length)
        {
            return request.Substring(bodyStart);
        }
    }
    
    return null;
}

// Helper method to compress data using gzip
static byte[] CompressWithGzip(byte[] data)
{
    using (var memoryStream = new MemoryStream())
    {
        using (var gzipStream = new GZipStream(memoryStream, CompressionMode.Compress))
        {
            gzipStream.Write(data, 0, data.Length);
        }
        return memoryStream.ToArray();
    }
}