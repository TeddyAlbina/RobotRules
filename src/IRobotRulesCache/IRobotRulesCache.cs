using System;
using System.Diagnostics.CodeAnalysis;

namespace BlueCurve.Search.RobotRules.Abstractions
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
        void Add([DisallowNull] string uri, [DisallowNull]string content);
        /// <summary>
        /// Delete a fil from the cache
        /// </summary>
        /// <param name="uri">Url</param>
        void Delete([DisallowNull]string uri);
        /// <summary>
        /// Update a document
        /// </summary>
        /// <param name="uri">Url</param>
        /// <param name="content">Robots file content</param>
        void Update([DisallowNull] string uri, [DisallowNull] string content);
        /// <summary>
        /// Check if a document exists in the cache
        /// </summary>
        /// <param name="uri">Url</param>
        bool CheckExist([DisallowNull] string uri);
        /// <summary>
        /// Get the robots rule control file
        /// </summary>
        /// <param name="uri">Url</param>
        /// <returns>File content</returns>
        [return: NotNull]
        string[]? GetRobotControlFile([DisallowNull] string uri);
        /// <summary>
        /// Get datetime when a document was added
        /// </summary>
        /// <param name="uri">Url</param>
        /// <returns>DateTime?</returns>
        DateTime? GetDate([DisallowNull] string uri);
    }
}
