using System;
using System.IO;
using System.Collections.Generic;

namespace PowerShellTerminal.Domain.Models
{
    public class CommandContext
    {
        public string CurrentDirectory { get; set; } = Directory.GetCurrentDirectory();
        public Dictionary<string, string> EnvironmentVars { get; set; } = new Dictionary<string, string>();
        public List<string> History { get; set; } = new List<string>();

        public void SetOutput(string output)
        {
            if (string.IsNullOrEmpty(output)) return;
            History.Add(output);
        }
    }
}
