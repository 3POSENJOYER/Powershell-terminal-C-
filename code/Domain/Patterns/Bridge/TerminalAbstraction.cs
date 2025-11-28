using System.Drawing;
using PowerShellTerminal.Domain.Patterns.Bridge;

namespace PowerShellTerminal.Domain.Patterns.Bridge
{
    public class TerminalAbstraction
    {
        private readonly IRenderer _renderer;

        public TerminalAbstraction(IRenderer renderer)
        {
            _renderer = renderer;
        }

        public void Write(string text, Color color)
        {
            _renderer?.RenderText(text, color);
        }

        public void Clear()
        {
            _renderer?.Clear();
        }
    }
}
