﻿document.getElementById('register').addEventListener('submit', handleRegisterSubmit);

async function handleRegisterSubmit(event) {
    event.preventDefault();

    //let username = this.username.value;
    let displayName = this.username.value;

    // possible values: none, direct, indirect
    let attestation_type = "direct";
    // possible values: <empty>, platform, cross-platform
    let authenticator_attachment = "";

    // possible values: preferred, required, discouraged
    let user_verification = "preferred";

    // possible values: discouraged, preferred, required
    // NOTE: For usernameless scenarios, resident key must be set to true.
    let residentKey = "required";



    // prepare form post data
    var data = new FormData();
    //data.append('username', username);
    data.append('displayName', displayName);
    data.append('attType', attestation_type);
    data.append('authType', authenticator_attachment);
    data.append('userVerification', user_verification);
    data.append('residentKey', residentKey);

    // send to server for registering
    let makeCredentialOptions;
    try {
        // 將參數傳送到伺服器建立 makeCredentialOptions
        makeCredentialOptions = await fetchMakeCredentialOptions(data);

    } catch (e) {
        console.error(e);
        let msg = "Something went really wrong";
        showErrorAlert(msg);
    }

    console.log("Credential Options Object", makeCredentialOptions);

    if (makeCredentialOptions.status !== "ok") {
        console.log("Error creating credential options");
        console.log(makeCredentialOptions.errorMessage);
        showErrorAlert(makeCredentialOptions.errorMessage);
        return;
    }

    // Turn the challenge back into the accepted format of padded base64
    // 伺服器隨機產生的 challenge
    makeCredentialOptions.challenge = coerceToArrayBuffer(makeCredentialOptions.challenge);
    // Turn ID into a UInt8Array Buffer for some reason
    makeCredentialOptions.user.id = coerceToArrayBuffer(makeCredentialOptions.user.id);

    // 應排除的憑證(若先前已註冊過)
    makeCredentialOptions.excludeCredentials = makeCredentialOptions.excludeCredentials.map((c) => {
        c.id = coerceToArrayBuffer(c.id);
        return c;
    });

    if (makeCredentialOptions.authenticatorSelection.authenticatorAttachment === null) 
        makeCredentialOptions.authenticatorSelection.authenticatorAttachment = undefined;

    console.log("Credential Options Formatted", makeCredentialOptions);

    Swal.fire({
        title: 'Registering...',
        text: 'Tap your security key to finish registration.',
        imageUrl: "/images/securitykey.min.svg",
        showCancelButton: true,
        showConfirmButton: false,
        focusConfirm: false,
        focusCancel: false
    });

    console.log("Creating PublicKeyCredential...");

    let newCredential;
    try {
        // 呼叫 WebAuthn API 建立公私鑰
        newCredential = await navigator.credentials.create({
            publicKey: makeCredentialOptions
        });
    } catch (e) {
        var msg = "Could not create credentials in browser. Probably because the username is already registered with your authenticator. Please change username or authenticator."
        console.error(msg, e);
        showErrorAlert(msg, e);
    }

    console.log("PublicKeyCredential Created", newCredential);

    try {
        // 將公鑰傳送到伺服器註冊
        registerNewCredential(newCredential);

    } catch (e) {
        showErrorAlert(err.message ? err.message : err);
    }
}

async function fetchMakeCredentialOptions(formData) {
    let response = await fetch('/fido2/makeCredentialOptions', {
        method: 'POST', // or 'PUT'
        body: formData, // data can be `string` or {object}!
        headers: {
            'Accept': 'application/json'
        }
    });

    let data = await response.json();

    return data;
}


// This should be used to verify the auth data with the server
async function registerNewCredential(newCredential) {
    // Move data into Arrays incase it is super long
    let attestationObject = new Uint8Array(newCredential.response.attestationObject);
    let clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
    let rawId = new Uint8Array(newCredential.rawId);

    const data = {
        id: newCredential.id,
        rawId: coerceToBase64Url(rawId),
        type: newCredential.type,
        extensions: newCredential.getClientExtensionResults(),
        response: {
            attestationObject: coerceToBase64Url(attestationObject),
            clientDataJSON: coerceToBase64Url(clientDataJSON)
        }
    };

    let response;
    try {
        response = await registerCredentialWithServer(data);
    } catch (e) {
        showErrorAlert(e);
    }

    console.log("Credential Object", response);

    // show error
    if (response.status !== "ok") {
        console.log("Error creating credential");
        console.log(response.errorMessage);
        showErrorAlert(response.errorMessage);
        return;
    }

    // show success 
    Swal.fire({
        title: 'Registration Successful!',
        text: 'You\'ve registered successfully.',
        type: 'success',
        timer: 2000
    }).then(() => {
        // 註冊成功後，導回首頁
        window.location.href = "/";
    });

    // redirect to dashboard?
    //window.location.href = "/dashboard/" + state.user.displayName;
}

async function registerCredentialWithServer(formData) {
    let response = await fetch('/fido2/makeCredential', {
        method: 'POST', // or 'PUT'
        body: JSON.stringify(formData), // data can be `string` or {object}!
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    });

    let data = await response.json();

    return data;
}
