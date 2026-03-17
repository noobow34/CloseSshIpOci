using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Oci.Common;
using Oci.Common.Auth;
using Oci.Common.Model;
using Oci.CoreService;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using System.Text.Json;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace CloseSshIpOci;

public class Function
{
    private static readonly string SUBNET_ID = Environment.GetEnvironmentVariable("OCI_SUBNET_ID") ?? throw new InvalidOperationException("OCI_SUBNET_ID is not set");
    private static readonly string USER_ID = Environment.GetEnvironmentVariable("OCI_USER_ID") ?? throw new InvalidOperationException("OCI_USER_ID is not set");
    private static readonly string FINGERPRINT = Environment.GetEnvironmentVariable("OCI_FINGERPRINT") ?? throw new InvalidOperationException("OCI_FINGERPRINT is not set");
    private static readonly string TENANCY_ID = Environment.GetEnvironmentVariable("OCI_TENANCY_ID") ?? throw new InvalidOperationException("OCI_TENANCY_ID is not set");
    private static readonly string PRIVATE_KEY = Environment.GetEnvironmentVariable("OCI_PRIVATE_KEY") ?? throw new InvalidOperationException("OCI_PRIVATE_KEY is not set");

    /// <summary>
    /// A simple function that takes a string and does a ToUpper
    /// </summary>
    /// <param name="input">The event for the Lambda function handler to process.</param>
    /// <param name="context">The ILambdaContext that provides methods for logging and describing the Lambda environment.</param>
    /// <returns></returns>
    public async Task<APIGatewayProxyResponse> FunctionHandlerAsync(JsonElement input, ILambdaContext context)
    {
        try
        {
            string createdSlistId = input.GetProperty("security_list_id").GetString() ?? string.Empty;
            context.Logger.LogInformation($"[INFO] close-ssh 開始: security_list_id={createdSlistId}");

            if (string.IsNullOrEmpty(createdSlistId))
            {
                context.Logger.LogWarning("[WARN] security_list_id が空です");
                return new APIGatewayProxyResponse
                {
                    StatusCode = 400,
                    Headers = new Dictionary<string, string> { { "Content-Type", "application/json" } },
                    Body = JsonSerializer.Serialize(new { error = "security_list_id is required" })
                };
            }

            // --- OCI 認証プロバイダー ---
            var provider = new SimpleAuthenticationDetailsProvider
            {
                UserId = USER_ID,
                Fingerprint = FINGERPRINT,
                TenantId = TENANCY_ID,
                Region = Oci.Common.Region.AP_TOKYO_1,
                PrivateKeySupplier = new StringPrivateKeySupplier(PRIVATE_KEY)
            };
            VirtualNetworkClient client = new(provider, new ClientConfiguration());

            // --- セキュリティリストの存在確認 ---
            bool securityListExists = false;
            try
            {
                var getSlRequest = new GetSecurityListRequest { SecurityListId = createdSlistId };
                var getSlResponse = await client.GetSecurityList(getSlRequest);
                securityListExists = getSlResponse.SecurityList != null;
                context.Logger.LogInformation($"[INFO] セキュリティリスト確認OK: {createdSlistId}");
            }
            catch (OciException ociEx) when (ociEx.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                context.Logger.LogWarning($"[WARN] セキュリティリストが存在しません（スキップ）: {createdSlistId}");
            }

            // --- サブネットからセキュリティリストを外す ---
            context.Logger.LogInformation($"[INFO] サブネット取得: {SUBNET_ID}");
            var subnetResponse = await client.GetSubnet(new GetSubnetRequest { SubnetId = SUBNET_ID });
            var subnet = subnetResponse.Subnet;

            if (subnet.SecurityListIds.Contains(createdSlistId))
            {
                subnet.SecurityListIds.Remove(createdSlistId);
                await client.UpdateSubnet(new UpdateSubnetRequest
                {
                    SubnetId = subnet.Id,
                    UpdateSubnetDetails = new UpdateSubnetDetails { SecurityListIds = subnet.SecurityListIds },
                });
                context.Logger.LogInformation($"[INFO] サブネットからデタッチ完了: {createdSlistId}");
            }
            else
            {
                context.Logger.LogWarning($"[WARN] サブネットにセキュリティリストが紐付いていません（スキップ）: {createdSlistId}");
            }

            // --- セキュリティリストの削除 ---
            if (securityListExists)
            {
                await client.DeleteSecurityList(new DeleteSecurityListRequest { SecurityListId = createdSlistId });
                context.Logger.LogInformation($"[INFO] セキュリティリスト削除完了: {createdSlistId}");
            }

            context.Logger.LogInformation($"[INFO] close-ssh 正常終了: security_list_id={createdSlistId}");

            return new APIGatewayProxyResponse
            {
                StatusCode = 200,
                Headers = new Dictionary<string, string> { { "Content-Type", "application/json" } },
                Body = JsonSerializer.Serialize(new { deleted = createdSlistId })
            };
        }
        catch (Exception ex)
        {
            context.Logger.LogError($"[ERROR] {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");

            var (statusCode, errorType) = ex switch
            {
                JsonException => (400, "Invalid JSON format"),
                KeyNotFoundException => (400, "Required parameter missing"),
                ArgumentException => (400, "Invalid argument"),
                UnauthorizedAccessException => (403, "Forbidden"),
                _ => (500, "Internal Server Error")
            };

            return new APIGatewayProxyResponse
            {
                StatusCode = statusCode,
                Headers = new Dictionary<string, string> { { "Content-Type", "application/json" } },
                Body = JsonSerializer.Serialize(new
                {
                    error = errorType,
                    message = ex.Message,
                    requestId = context.AwsRequestId
                })
            };
        }
    }
}
