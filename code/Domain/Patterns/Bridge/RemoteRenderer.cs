using System.Drawing;
using System;
using System.Net.Sockets;
using System.Text;
using PowerShellTerminal.Domain.Patterns.Bridge;

namespace PowerShellTerminal.Domain.Patterns.Bridge
{
    public class RemoteRenderer : IRenderer
    {
        private readonly string _host;
        private readonly int _port;

        public RemoteRenderer(string host, int port)
        {
            _host = host;
            _port = port;
        }

        public void RenderText(string text, Color color)
        {
            try
            {
                using var client = new TcpClient();
                client.Connect(_host, _port);
                var stream = client.GetStream();
                var bytes = Encoding.UTF8.GetBytes(text + "\n");
                stream.Write(bytes, 0, bytes.Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"RemoteRenderer error: {ex.Message}");
            }
        }

        public void Clear()
        {
        }
    }
}
