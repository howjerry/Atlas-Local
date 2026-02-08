using System;

namespace RedundantBoolExample
{
    public class PassExample
    {
        public void CheckStatus(bool isActive, bool isReady)
        {
            if (isActive)
            {
                Console.WriteLine("Active");
            }

            if (!isReady)
            {
                Console.WriteLine("Not ready");
            }

            bool result = !isActive;
        }
    }
}
