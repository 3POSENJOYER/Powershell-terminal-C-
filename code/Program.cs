using System;
using System.Windows.Forms;
using PowerShellTerminal.Infrastructure;
using WinFormsApp = System.Windows.Forms.Application;

namespace PowerShellTerminal
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            DatabaseInitializer.Initialize();

            WinFormsApp.EnableVisualStyles();
            WinFormsApp.SetCompatibleTextRenderingDefault(false);

            WinFormsApp.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            WinFormsApp.ThreadException += (s, e) =>
                MessageBox.Show($"Error: {e.Exception.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
                MessageBox.Show($"Fatal error: {(e.ExceptionObject as Exception)?.Message}", "Fatal Error", MessageBoxButtons.OK, MessageBoxIcon.Error);

            try
            {
                WinFormsApp.Run(new MainForm());
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Startup error: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
