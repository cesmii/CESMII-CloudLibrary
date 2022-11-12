using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Opc.Ua.Cloud.Library.Client;
using Opc.Ua.Export;

namespace Opc.Ua.CloudLib.Sync
{
    /// <summary>
    /// Sync, Upload and download nodeset between cloud libraries
    /// </summary>
    public class CloudLibSync
    {
        /// <summary>
        /// Create a CloudLibSync instance
        /// </summary>
        /// <param name="logger"></param>
        public CloudLibSync(ILogger logger)
        {
            _logger = logger;
        }
        private readonly ILogger _logger;
        /// <summary>
        /// Downloads node sets from a cloud library to a local directory
        /// </summary>
        /// <param name="sourceUrl"></param>
        /// <param name="sourceUserName"></param>
        /// <param name="sourcePassword"></param>
        /// <param name="localDir"></param>
        /// <param name="nodeSetXmlDir"></param>
        /// <returns></returns>
        public async Task DownloadAsync(string sourceUrl, string sourceUserName, string sourcePassword, string localDir, string nodeSetXmlDir)
        {
            var sourceClient = new UACloudLibClient(sourceUrl, sourceUserName, sourcePassword);

            GraphQlResult<Nodeset> nodeSetResult;
            string? cursor = null;
            do
            {
                // Get all infomodels
                nodeSetResult = await sourceClient.GetNodeSets(after: cursor, first: 50).ConfigureAwait(false);

                foreach (var nodeSetAndCursor in nodeSetResult.Edges)
                {
                    // Download each infomodel
                    var identifier = nodeSetAndCursor.Node.Identifier.ToString(CultureInfo.InvariantCulture);
                    var uaNameSpace = await sourceClient.DownloadNodesetAsync(identifier).ConfigureAwait(false);

                    if (uaNameSpace?.Nodeset != null)
                    {
                        if (!Directory.Exists(localDir))
                        {
                            Directory.CreateDirectory(localDir);
                        }

                        string? namespaceUri = VerifyAndFixupNodeSetMeta(uaNameSpace.Nodeset);

                        var fileName = GetFileNameForNamespaceUri(namespaceUri);
                        File.WriteAllText(Path.Combine(localDir, $"{fileName}.{identifier}.json"), JsonConvert.SerializeObject(uaNameSpace));
                        _logger.LogInformation($"Downloaded {namespaceUri}, {identifier}");

                        if (nodeSetXmlDir != null)
                        {
                            SaveNodeSetAsXmlFile(uaNameSpace, nodeSetXmlDir);
                        }
                    }
                }
                cursor = nodeSetResult.PageInfo.EndCursor;
            }
            while (nodeSetResult.PageInfo.HasNextPage);
        }

        /// <summary>
        /// Synchronizes from one cloud lib to another.
        /// </summary>
        /// <param name="sourceUrl"></param>
        /// <param name="sourceUserName"></param>
        /// <param name="sourcePassword"></param>
        /// <param name="targetUrl"></param>
        /// <param name="targetUserName"></param>
        /// <param name="targetPassword"></param>
        /// <returns></returns>
        public async Task SynchronizeAsync(string sourceUrl, string sourceUserName, string sourcePassword, string targetUrl, string targetUserName, string targetPassword)
        {
            var sourceClient = new UACloudLibClient(sourceUrl, sourceUserName, sourcePassword);
            var targetClient = new UACloudLibClient(targetUrl, targetUserName, targetPassword);

            bool bAdded;
            do
            {
                List<Nodeset> targetNodesets = new();
                GraphQlResult<Nodeset> targetNodeSetResult;
                string? targetCursor = null;
                do
                {
                    targetNodeSetResult = await targetClient.GetNodeSets(after: targetCursor, first: 50).ConfigureAwait(false);
                    targetNodesets.AddRange(targetNodeSetResult.Edges.Select(e => e.Node));
                    targetCursor = targetNodeSetResult.PageInfo.EndCursor;
                } while (targetNodeSetResult.PageInfo.HasNextPage);

                bAdded = false;

                GraphQlResult<Nodeset> sourceNodeSetResult;
                string? sourceCursor = null;
                do
                {
                    sourceNodeSetResult = await sourceClient.GetNodeSets(after: sourceCursor, first: 50).ConfigureAwait(false);

                    // Get the ones that are not already on the target
                    var toSync = sourceNodeSetResult.Edges
                        .Select(e => e.Node)
                        .Where(source => !targetNodesets
                            .Any(target =>
                                source.NamespaceUri?.ToString() == target.NamespaceUri?.ToString()
                                && (source.PublicationDate == target.PublicationDate || (source.Identifier != 0 && source.Identifier == target.Identifier))
                        )).ToList();
                    foreach (var nodeSet in toSync)
                    {
                        // Download each infomodel
                        var identifier = nodeSet.Identifier.ToString(CultureInfo.InvariantCulture);
                        var uaNamespace = await sourceClient.DownloadNodesetAsync(identifier).ConfigureAwait(false);

                        try
                        {
                            VerifyAndFixupNodeSetMeta(uaNamespace.Nodeset);
                            // upload infomodel to target cloud library
                            var response = await targetClient.UploadNodeSetAsync(uaNamespace).ConfigureAwait(false);
                            if (response.Status == System.Net.HttpStatusCode.OK)
                            {
                                bAdded = true;
                                _logger.LogInformation($"Uploaded {uaNamespace.Nodeset.NamespaceUri}, {identifier}");
                            }
                            else
                            {
                                _logger.LogError($"Error uploading {uaNamespace.Nodeset.NamespaceUri}, {identifier}: {response.Status} {response.Message}");
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error uploading {uaNamespace.Nodeset.NamespaceUri}, {identifier}: {ex.Message}");
                        }
                    }
                    sourceCursor = sourceNodeSetResult.PageInfo.EndCursor;
                } while (sourceNodeSetResult.PageInfo.HasNextPage);
            } while (bAdded);
        }

        /// <summary>
        /// Uploads nodesets from a local directory to a cloud library
        /// </summary>
        /// <param name="targetUrl"></param>
        /// <param name="targetUserName"></param>
        /// <param name="targetPassword"></param>
        /// <param name="localDir"></param>
        /// <param name="fileName"></param>
        /// <returns></returns>
        public async Task UploadAsync(string targetUrl, string targetUserName, string targetPassword, string localDir, string fileName)
        {
            var targetClient = new UACloudLibClient(targetUrl, targetUserName, targetPassword);

            var filesToUpload = new List<string>();
            if (!string.IsNullOrEmpty(fileName))
            {
                filesToUpload.Add(fileName);
            }
            else
            {
                filesToUpload.AddRange(Directory.GetFiles(localDir));
            }

            foreach (var file in filesToUpload)
            {
                var uploadJson = File.ReadAllText(file);

                var addressSpace = JsonConvert.DeserializeObject<UANameSpace>(uploadJson);
                var response = await targetClient.UploadNodeSetAsync(addressSpace).ConfigureAwait(false);
                if (response.Status == System.Net.HttpStatusCode.OK)
                {
                    _logger.LogInformation($"Uploaded {addressSpace?.Nodeset.NamespaceUri}, {addressSpace?.Nodeset.Identifier}");
                }
                else
                {
                    _logger.LogError($"Error uploading {addressSpace?.Nodeset.NamespaceUri}, {addressSpace?.Nodeset.Identifier}: {response.Status} {response.Message}");
                }
            }
        }

        private string? VerifyAndFixupNodeSetMeta(Nodeset nodeset)
        {
            var namespaceUri = nodeset?.NamespaceUri?.ToString();

            if (nodeset?.NodesetXml != null)
            {
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(nodeset.NodesetXml)))
                {
                    var nodeSet = UANodeSet.Read(ms);
                    var firstModel = nodeSet.Models?.FirstOrDefault();
                    if (firstModel != null)
                    {
                        if (firstModel.PublicationDateSpecified && firstModel.PublicationDate != DateTime.MinValue && firstModel.PublicationDate != nodeset.PublicationDate)
                        {
                            _logger.LogWarning($"Publication date {nodeset.PublicationDate} in meta data does not match nodeset {firstModel.PublicationDate}. Fixed up.");
                            nodeset.PublicationDate = firstModel.PublicationDate;
                        }
                        if (firstModel.Version != nodeset.Version)
                        {
                            _logger.LogWarning($"Version  {nodeset.Version} in meta data does not match nodeset {firstModel.Version}. Fixed up.");
                            nodeset.Version = firstModel.Version;
                        }
                        if (nodeSet.LastModifiedSpecified && nodeSet.LastModified != nodeset.LastModifiedDate)
                        {
                            _logger.LogWarning($"Last modified date {nodeset.LastModifiedDate} in meta data does not match nodeset {nodeSet.LastModified}. Fixed up.");
                            nodeset.LastModifiedDate = nodeSet.LastModified;
                        }
                        if (namespaceUri == null)
                        {
                            namespaceUri = nodeSet.Models?.FirstOrDefault()?.ModelUri;
                        }
                    }
                }
            }

            return namespaceUri;
        }

        private static string GetFileNameForNamespaceUri(string? modelUri)
        {
            var tFile = modelUri?.Replace("http://", "", StringComparison.OrdinalIgnoreCase) ?? "";
            tFile = tFile.Replace('/', '.');
            tFile = tFile.Replace(':', '_');
            if (!tFile.EndsWith(".", StringComparison.Ordinal)) tFile += ".";
            tFile = $"{tFile}NodeSet2.xml";
            return tFile;
        }

        static void SaveNodeSetAsXmlFile(UANameSpace? nameSpace, string directoryPath)
        {
            var modelUri = nameSpace?.Nodeset?.NamespaceUri?.ToString();
            if (modelUri == null && nameSpace?.Nodeset != null)
            {
                var ms = new MemoryStream(Encoding.UTF8.GetBytes(nameSpace.Nodeset.NodesetXml));
                var model = UANodeSet.Read(ms);
                modelUri = model.Models?.FirstOrDefault()?.ModelUri;
            }
            string tFile = GetFileNameForNamespaceUri(modelUri);
            string filePath = Path.Combine(directoryPath, tFile);
            if (!Directory.Exists(directoryPath))
            {
                Directory.CreateDirectory(directoryPath);
            }
            File.WriteAllText(filePath, nameSpace?.Nodeset.NodesetXml);
        }
    }
}
