using WinFormsApp = System.Windows.Forms.Application;
using System;
using System.Windows.Forms;
using PowerShellTerminal.Infrastructure;

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
            WinFormsApp.ThreadException += Application_ThreadException;
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;

            try
            {
                WinFormsApp.Run(new MainForm());
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to start application: {ex.Message}", "Startup Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static void Application_ThreadException(object sender, System.Threading.ThreadExceptionEventArgs e)
        {
            MessageBox.Show($"Error: {e.Exception.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            MessageBox.Show($"Fatal error: {(e.ExceptionObject as Exception)?.Message}", "Fatal Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
