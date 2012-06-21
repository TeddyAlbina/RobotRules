using System;

namespace RobotRules.Exception
{
    /// <summary>
    ///   The base class for exceptions thrown when an error occurs that is related to Internet robots.
    /// </summary>
    public abstract class RobotException : ApplicationException
    {
        public RobotException()
        {
        }

        public RobotException(string message)
            : base(message)
        {
        }

        public RobotException(string message, System.Exception inner)
            : base(message, inner)
        {
        }
    }
}