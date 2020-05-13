namespace BlueCurve.Search.RobotRules.Exception
{
    /// <summary>
    ///   The exception that is thrown when the specified URI does not match the site to which the robot control file referred.
    /// </summary>
    public class SiteMismatchException : RobotException
    {
        private const string DefaultMessage =
            "The parser cannot evaluate the URI because it is part of a different site.";


        public SiteMismatchException()
            : base(DefaultMessage)
        {
        }

        public SiteMismatchException(string message)
            : base(message)
        {
        }

        public SiteMismatchException(string message, System.Exception inner)
            : base(message, inner)
        {
        }
    }
}