using System.Drawing;
using System.IO;
using PowerShellTerminal.Domain.Patterns.Bridge;

namespace PowerShellTerminal.Domain.Patterns.Bridge
{
    public class FileRenderer : IRenderer
    {
        private readonly string _path;

        public FileRenderer(string path)
        {
            _path = path;
        }

        public void RenderText(string text, Color color)
        {
            try
            {
                File.AppendAllText(_path, text + System.Environment.NewLine);
            }
            catch { }
        }

        public void Clear()
        {
            try { File.WriteAllText(_path, string.Empty); } catch { }
        }
    }
}
