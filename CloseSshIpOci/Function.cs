using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Oci.Common;
using Oci.Common.Auth;
using Oci.Common.Model;
using Oci.CoreService;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace CloseSshIpOci;

public class Function
{
    private static readonly string SUBNET_ID = Environment.GetEnvironmentVariable("OCI_SUBNET_ID") ?? throw new InvalidOperationException("OCI_SUBNET_ID is not set");
    private static readonly string USER_ID = Environment.GetEnvironmentVariable("OCI_USER_ID") ?? throw new InvalidOperationException("OCI_USER_ID is not set");
    private static readonly string FINGERPRINT = Environment.GetEnvironmentVariable("OCI_FINGERPRINT") ?? throw new InvalidOperationException("OCI_FINGERPRINT is not set");
    private static readonly string TENANCY_ID = Environment.GetEnvironmentVariable("OCI_TENANCY_ID") ?? throw new InvalidOperationException("OCI_TENANCY_ID is not set");
    private static readonly string PRIVATE_KEY = Environment.GetEnvironmentVariable("OCI_PRIVATE_KEY") ?? throw new InvalidOperationException("OCI_PRIVATE_KEY is not set");

    public async Task<APIGatewayProxyResponse> FunctionHandlerAsync(JsonElement input, ILambdaContext context)
    {
        try
        {
            string createdSlistId = input.GetProperty("security_list_id").GetString() ?? string.Empty;
            context.Logger.LogInformation($"[INFO] close-ssh 開始: security_list_id={createdSlistId}");

            if (string.IsNullOrEmpty(createdSlistId))
            {
                context.Logger.LogWarning("[WARN] security_list_id が空です");
                await SendSlackNotificationAsync(":warning: *close-ssh 失敗*\n`security_list_id` が空です。", context);
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

            await SendSlackNotificationAsync(
                $":white_check_mark: *close-ssh 成功*\nセキュリティリスト `{createdSlistId}` を削除し、SSHアクセスを閉じました。",
                context
            );

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

            await SendSlackNotificationAsync(
                $":x: *close-ssh 失敗*\n`{errorType}`: {ex.Message}",
                context
            );

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

    private static async Task SendSlackNotificationAsync(string message, ILambdaContext context)
    {
        try
        {
            var token = Environment.GetEnvironmentVariable("SLACK_BOT_TOKEN");
            var channelId = Environment.GetEnvironmentVariable("SLACK_CHANNEL");

            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(channelId))
            {
                context.Logger.LogWarning("[WARN] SLACK_BOT_TOKEN または SLACK_CHANNEL が未設定のため、Slack通知をスキップします");
                return;
            }

            var payload = new
            {
                channel = channelId,
                text = message
            };
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", token);
            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await client.PostAsync(
                "https://slack.com/api/chat.postMessage",
                content
            );

            if (!response.IsSuccessStatusCode)
            {
                context.Logger.LogWarning($"[WARN] Slack通知失敗: HTTP {(int)response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            // Slack通知の失敗はメイン処理に影響させない
            context.Logger.LogWarning($"[WARN] Slack通知中に例外: {ex.Message}");
        }
    }
}