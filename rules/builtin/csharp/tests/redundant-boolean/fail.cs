using System;

namespace RedundantBoolExample
{
    public class FailExample
    {
        public void CheckStatus(bool isActive, bool isReady)
        {
            if (isActive == true)
            {
                Console.WriteLine("Active");
            }

            if (isReady != false)
            {
                Console.WriteLine("Ready");
            }

            bool result = isActive == false;
        }
    }
}
