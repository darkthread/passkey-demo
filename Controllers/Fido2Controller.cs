using System.Text;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;
using Fido2NetLib;
using Microsoft.AspNetCore.Mvc;
using static Fido2NetLib.Fido2;

namespace passkey_demo.Controllers
{
    public class Fido2Controller : Controller
    {
        private IFido2 _fido2;
        // 使用檔案保存使用者註冊資料
        public static DevelopmentFileStore DemoStorage = null!;

        public Fido2Controller(IFido2 fido2, DevelopmentFileStore demoStore)
        {
            DemoStorage = demoStore;
            _fido2 = fido2;
        }

        private string FormatException(Exception e)
        {
            return string.Format("{0}{1}", e.Message, e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
        }

        // 前端註冊前呼叫，產生 CredentialCreateOptions 傳至客戶端呼叫 navigator.credentials.create() 建立憑證
        [HttpPost]
        public JsonResult MakeCredentialOptions([FromForm] string username,
                                                [FromForm] string displayName,
                                                [FromForm] string attType,
                                                [FromForm] string authType,
                                                [FromForm] string residentKey,
                                                [FromForm] string userVerification)
        {
            try
            {

                if (string.IsNullOrEmpty(username))
                {
                    username = displayName;
                }

                // 1. Get user from DB by username (in our example, auto create missing users)
                // 檢查使用者是否存在，若不存在則建立新使用者資料
                var user = DemoStorage.GetOrAddUser(username, () => new Fido2User
                {
                    DisplayName = displayName,
                    Name = username,
                    Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
                });

                // 2. Get user existing keys by username
                // 檢查使用者是否已註冊憑證
                var existingKeys = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

                // 3. Create options
                var authenticatorSelection = new AuthenticatorSelection
                {
                    // require resident key (passkey)
                    // 是否要求用 Passkey (Discoverable Credential)
                    ResidentKey = residentKey.ToEnum<ResidentKeyRequirement>(),
                    // require user verification
                    // 是否要驗證使用者 (PIN 或生物辨識)
                    UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
                };
                if (!string.IsNullOrEmpty(authType))
                    // 空白表不指定，platform (Windows Hello, FaceID...), cross-platform (Security Key, YubiKey...)
                    authenticatorSelection.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();

                var exts = new AuthenticationExtensionsClientInputs()
                {
                    Extensions = true,
                    UserVerificationMethod = true,
                    DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs() { Attestation = attType },
                    CredProps = true
                };

                var options = _fido2.RequestNewCredential(user, 
                    existingKeys, // 傳入已註冊的憑證，避免重複註冊
                    authenticatorSelection, attType.ToEnum<AttestationConveyancePreference>(), exts);

                // 4. Temporarily store options, session/in-memory cache/redis/db
                // 將 options 暫存至 Session
                HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

                // 5. return options to client
                return Json(options);
            }
            catch (Exception e)
            {
                return Json(new CredentialCreateOptions { Status = "error", ErrorMessage = FormatException(e) });
            }
        }

        // 將已登入的使用者名稱暫存至 Session
        void SaveUserIdToSession(string username)
        {
            // TODO: Write a user context module to keep user session
            HttpContext.Session.SetString("UserId", username);
        }

        [HttpPost]
        public async Task<JsonResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse attestationResponse, CancellationToken cancellationToken)
        {
            try
            {
                // 1. get the options we sent the client
                // 由 Session 取得並還原註冊憑證參數
                var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
                var options = CredentialCreateOptions.FromJson(jsonOptions);

                // 2. Create callback so that lib can verify credential id is unique to this user
                // 檢查憑證是否已註冊過
                IsCredentialIdUniqueToUserAsyncDelegate callback = static async (args, cancellationToken) =>
                {
                    var users = await DemoStorage.GetUsersByCredentialIdAsync(args.CredentialId, cancellationToken);
                    if (users.Count > 0)
                        return false;

                    return true;
                };

                // 2. Verify and make the credentials
                // 驗證並建立憑證物件
                var success = await _fido2.MakeNewCredentialAsync(attestationResponse, options, callback, cancellationToken: cancellationToken);

                // 3. Store the credentials in db
                var cred = success.Result!;
                // 將憑證關聯至使用者
                DemoStorage.AddCredentialToUser(options.User, new StoredCredential
                {
                    // 由 Result.Id 取得憑證 ID
                    Id = cred.Id,
                    Descriptor = new PublicKeyCredentialDescriptor(cred.Id),
                    PublicKey = cred.PublicKey,
                    UserHandle = cred.User.Id,
                    SignCount = cred.SignCount,
                    AttestationFormat = cred.AttestationFormat,
                    RegDate = DateTimeOffset.UtcNow,
                    AaGuid = cred.AaGuid,
                    Transports = cred.Transports,
                    IsBackupEligible = cred.IsBackupEligible,
                    IsBackedUp = cred.IsBackedUp,
                    AttestationObject = cred.AttestationObject,
                    AttestationClientDataJson = cred.AttestationClientDataJson,
                    DevicePublicKeys = new List<byte[]>() { cred.DevicePublicKey }
                });
                
                // 將使用者名稱暫存至 Session，模擬已登入
                SaveUserIdToSession(cred.User.Name);

                // 4. return "ok" to the client
                return Json(success);
            }
            catch (Exception e)
            {
                return Json(new CredentialMakeResult("error", FormatException(e), null!));
            }
        }

        // 前端登入前呼叫，產生 AssertionOptions 傳至客戶端呼叫 navigator.credentials.get() 建立憑證
        [HttpPost]
        public ActionResult PostAssertionOptions([FromForm] string username, [FromForm] string userVerification)
        {
            try
            {
                var existingCredentials = new List<PublicKeyCredentialDescriptor>();

                if (!string.IsNullOrEmpty(username))
                {
                    // 1. Get user from DB
                    // 由資料查詢是否有此使用者
                    var user = DemoStorage.GetUser(username) ?? throw new ArgumentException("Username was not registered");

                    // 2. Get registered credentials from database
                    // 取得使用者註冊的憑證
                    existingCredentials = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();
                }

                var exts = new AuthenticationExtensionsClientInputs()
                {
                    Extensions = true,
                    UserVerificationMethod = true,
                    DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs()
                };

                // 3. Create options
                // 產生 AssertionOptions
                var uv = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();
                var options = _fido2.GetAssertionOptions(
                    existingCredentials,
                    uv,
                    exts
                );

                // 4. Temporarily store options, session/in-memory cache/redis/db
                // 將 AssertionOptions 暫存至 Session
                HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

                // 5. Return options to client
                return Json(options);
            }

            catch (Exception e)
            {
                return Json(new AssertionOptions { Status = "error", ErrorMessage = FormatException(e) });
            }
        }

        [HttpPost]
        public async Task<JsonResult> MakeAssertion([FromBody] AuthenticatorAssertionRawResponse clientResponse, CancellationToken cancellationToken)
        {
            try
            {
                // 1. Get the assertion options we sent the client
                // 由 Session 取得並還原登入 AssertionOptions
                var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
                var options = AssertionOptions.FromJson(jsonOptions);

                // 2. Get registered credential from database
                // 由憑證 ID 取得憑證資料
                var creds = DemoStorage.GetCredentialById(clientResponse.Id) ?? throw new Exception("Unknown credentials");

                // 3. Get credential counter from database
                // 取得憑證簽名計數器
                var storedCounter = creds.SignCount;

                // 4. Create callback to check if the user handle owns the credentialId
                IsUserHandleOwnerOfCredentialIdAsync callback = static async (args, cancellationToken) =>
                {
                    // 由 UserHandle 取得使用者註冊憑證，比對憑證 ID 是否相同
                    var storedCreds = await DemoStorage.GetCredentialsByUserHandleAsync(args.UserHandle, cancellationToken);
                    return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
                };

                // 5. Make the assertion
                // 建立 Assertion
                var res = await _fido2.MakeAssertionAsync(clientResponse, options, creds.PublicKey, creds.DevicePublicKeys, storedCounter, callback, cancellationToken: cancellationToken);

                // 6. Store the updated counter
                // 更新憑證簽名計數器
                DemoStorage.UpdateCounter(res.CredentialId, res.SignCount);

                if (res.DevicePublicKey is not null)
                    // 憑證資料加入裝置的公鑰 (私鑰可攜情境，公私鑰可在不同裝置間移轉)
                    creds.DevicePublicKeys.Add(res.DevicePublicKey);

                // 將使用者名稱暫存至 Session，模擬已登入
                SaveUserIdToSession(DemoStorage.GetUserById(creds.UserId)?.Name);

                // 7. return OK to client
                return Json(res);
            }
            catch (Exception e)
            {
                return Json(new VerifyAssertionResult { Status = "error", ErrorMessage = FormatException(e) });
            }
        }
    }
}
