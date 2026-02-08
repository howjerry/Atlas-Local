using System;

namespace EmptyMethodExample
{
    public class PassExample
    {
        public void OnEvent(EventArgs e)
        {
            HandleEvent(e);
        }

        public void Initialize()
        {
            LoadConfiguration();
            SetupDefaults();
        }

        protected void OnDataReceived(byte[] data)
        {
            ProcessData(data);
        }

        private void HandleEvent(EventArgs e) { Console.WriteLine(e); }
        private void LoadConfiguration() { }
        private void SetupDefaults() { }
        private void ProcessData(byte[] data) { Console.WriteLine(data.Length); }
    }

    // Abstract methods use semicolons, not empty blocks -- they won't match.
    public abstract class AbstractHandler
    {
        public abstract void Handle(string input);
    }
}
