using System;

namespace EmptyMethodExample
{
    public class FailExample
    {
        public void OnEvent(EventArgs e) { }

        public void Initialize()
        {
        }

        protected void OnDataReceived(byte[] data)
        {
        }
    }
}
