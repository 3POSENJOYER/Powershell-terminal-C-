using System.Drawing;
using PowerShellTerminal.Domain.Patterns.Bridge;
using PowerShellTerminal.Domain.Models;

namespace PowerShellTerminal.Domain.Patterns.Bridge
{
    public class GuiRenderer : IRenderer
    {
        private readonly TerminalControl _control;

        public GuiRenderer(TerminalControl control)
        {
            _control = control;
        }

        public void RenderText(string text, Color color)
        {
            _control.WriteLine(text, color);
        }

        public void Clear()
        {
            _control.ClearOutput();
        }
    }
}
