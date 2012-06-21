/*======================================================================
== Copyright : BlueCurve (c)
== Licence   : Gnu/GPL v2.x
== Author    : Teddy Albina
== Email     : bluecurveteam@gmail.com
== Web site  : http://www.codeplex.com/BlueCurve
========================================================================*/
using System;

namespace IRobotCache
{
    /// <summary>
    /// Interface for robot cache
    /// </summary>
    public interface IRobotRulesCache
    {
        /// <summary>
        /// Add a file to the cache
        /// </summary>
        /// <param name="uri">Url</param>
        /// <param name="content">Robots file content</param>
        void Add(string uri, string content);
        /// <summary>
        /// Delete a fil from the cache
        /// </summary>
        /// <param name="uri">Url</param>
        void Delete(string uri);
        /// <summary>
        /// Update a document
        /// </summary>
        /// <param name="uri">Url</param>
        /// <param name="content">Robots file content</param>
        void Update(string uri, string content);
        /// <summary>
        /// Check if a document exists in the cache
        /// </summary>
        /// <param name="uri">Url</param>
        bool CheckExist(string uri);
        /// <summary>
        /// Get the robots rule control file
        /// </summary>
        /// <param name="uri">Url</param>
        /// <returns>File content</returns>
        string[] GetRobotControlFile(string uri);
        /// <summary>
        /// Get datetime when a document was added
        /// </summary>
        /// <param name="uri">Url</param>
        /// <returns>DateTime?</returns>
        DateTime? GetDate(string uri);
    }
}
