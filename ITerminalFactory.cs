using System.Drawing;

public interface ITerminalFactory
{
    ITerminalControl CreateTerminalControl();
    ITerminalTheme CreateTheme();
    ICommandInterpreter CreateInterpreter();
}

public class DarkTerminalFactory : ITerminalFactory
{
    public ITerminalControl CreateTerminalControl() => new SimpleTerminalControl();
    public ITerminalTheme CreateTheme() => new DarkTheme();
    public ICommandInterpreter CreateInterpreter() => new PowerShellInterpreter();
}

public class LightTerminalFactory : ITerminalFactory
{
    public ITerminalControl CreateTerminalControl() => new SimpleTerminalControl();
    public ITerminalTheme CreateTheme() => new LightTheme();
    public ICommandInterpreter CreateInterpreter() => new PowerShellInterpreter();
}