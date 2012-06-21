using System;

namespace RobotRules.Exception
{
    /// <summary>
    ///   The exception that is thrown when a robot control file cannot be downloaded due to a transfer problem (not just an HTTP status code indicating failure).
    /// </summary>
    public class DownloadFailedException : RobotException
    {
        private const string DefaultMessage = "The download failed.";


        public DownloadFailedException()
            : base(DefaultMessage)
        {
        }

        public DownloadFailedException(Uri address)
            : base(DefaultMessage)
        {
            Address = address;
        }

        public DownloadFailedException(Uri address, System.Exception inner)
            : base(DefaultMessage)
        {
            Address = address;
        }

        public DownloadFailedException(string message, Uri address)
            : base(message)
        {
            Address = address;
        }

        public DownloadFailedException(string message, Uri address, System.Exception inner)
            : base(message, inner)
        {
            Address = address;
        }

        public Uri Address { get; private set; }


        public override string Message
        {
            get { return base.Message + Environment.NewLine + Address; }
        }
    }
}