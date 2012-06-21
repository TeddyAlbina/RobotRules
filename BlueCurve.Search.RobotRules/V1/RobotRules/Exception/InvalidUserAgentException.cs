/*======================================================================
== Copyright : BlueCurve (c)
== Licence   : Gnu/GPL v2.x
== Author    : Teddy Albina
== Email     : bluecurveteam@gmail.com
== Web site  : http://www.codeplex.com/BlueCurve
========================================================================*/

using System;

namespace RobotRules.Exception
{
    /// <summary>
    ///   The exception that is thrown when an invalid user agent token is specified.
    /// </summary>
    public class InvalidUserAgentException : RobotException
    {
        private const string DefaultMessage = "The user agent token is invalid.";


        public InvalidUserAgentException(string userAgent)
            : base(DefaultMessage)
        {
            UserAgent = userAgent;
        }

        public InvalidUserAgentException(string userAgent, System.Exception inner)
            : base(DefaultMessage, inner)
        {
            UserAgent = userAgent;
        }

        public InvalidUserAgentException(string message, string userAgent)
            : base(message)
        {
            UserAgent = userAgent;
        }

        public InvalidUserAgentException(string message, string userAgent, System.Exception inner)
            : base(message, inner)
        {
            UserAgent = userAgent;
        }

        public string UserAgent { get; set; }


        public override string Message
        {
            get { return base.Message + Environment.NewLine + UserAgent; }
        }
    }
}