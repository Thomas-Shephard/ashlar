namespace Ashlar.Sample.AspNetCore.Views;

internal static class AppViews
{
    private const string AdminLink = """<a href="/admin">Administration</a>""";

    private const string SharedScripts = """
        const sampleErrorMessages = {
            handshake_not_found: 'Your sign-in session has expired. Request a new magic link and try again.',
            invalid_email: 'Enter a valid email address.',
            invalid_invitation: 'This invitation is invalid or has expired. Ask an administrator to send a new invitation.',
            invalid_mfa_code: 'That verification code was not accepted. Check the code and try again.',
            invalid_totp: 'That authenticator code was not accepted. Check the code and try again.',
            last_admin_cannot_be_disabled: 'You cannot disable the last active administrator.',
            rate_limited: 'Too many attempts. Wait a moment, then try again.',
            user_exists: 'A user with this email address already exists.'
        };

        function formatSampleError(error, fallback) {
            if (!error) return fallback;
            if (sampleErrorMessages[error]) return sampleErrorMessages[error];
            const message = String(error)
                .replace(/_/g, ' ')
                .replace(/\b\w/g, c => c.toUpperCase());
            return /[.!?]$/.test(message) ? message : message + '.';
        }

        function setupForm(id, urlOrBuilder, method, bodyMapper, successMapper) {
            const form = document.getElementById(id);
            if (!form) return;
            form.onsubmit = async (e) => {
                e.preventDefault();
                const btn = e.target.querySelector('button');
                const resDiv = document.getElementById(id + 'Result');
                if (btn) btn.disabled = true;
                resDiv.innerText = 'Processing...';
                try {
                    const url = typeof urlOrBuilder === 'function' ? urlOrBuilder(e.target) : urlOrBuilder;
                    const response = await ashlarFetchWithStepUp(url, {
                        method: method,
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(bodyMapper(e.target))
                    });

                    let result = {};
                    if (response.status !== 204 && response.headers.get('Content-Type')?.includes('application/json')) {
                        try { result = await response.json(); } catch (e) { }
                    }

                    if (response.ok) {
                        successMapper(result, resDiv);
                    } else {
                        resDiv.style.color = '#dc2626';
                        resDiv.innerText = formatSampleError(result.error || result.ErrorMessage, 'Request failed.');
                    }
                } catch (err) {
                    resDiv.style.color = '#dc2626';
                    resDiv.innerText = 'Connection error.';
                } finally {
                    if (btn) btn.disabled = false;
                }
            };
        }

        let ashlarStepUpPromise = null;

        function ensureStepUpModal() {
            let modal = document.getElementById('stepUpModal');
            if (modal) return modal;

            const style = document.createElement('style');
            style.textContent = `
                body.step-up-modal-open { overflow: hidden; }
                .step-up-backdrop { position: fixed; inset: 0; background: rgba(17, 24, 39, 0.45); display: none; align-items: center; justify-content: center; padding: 1rem; z-index: 1000; }
                .step-up-backdrop.active { display: flex; }
                .step-up-dialog { background: #fff; border-radius: 8px; box-shadow: 0 20px 40px rgba(17, 24, 39, 0.25); width: min(100%, 420px); max-height: calc(100vh - 2rem); overflow: auto; padding: 1.5rem; }
                .step-up-dialog h2 { margin-top: 0; }
                .step-up-dialog .actions { display: flex; gap: 0.75rem; justify-content: flex-end; margin-top: 1rem; }
                .step-up-dialog .actions button { width: auto; }
                .step-up-setup { display: none; }
            `;
            document.head.appendChild(style);

            modal = document.createElement('div');
            modal.id = 'stepUpModal';
            modal.className = 'step-up-backdrop';
            modal.innerHTML = `
                <div class="step-up-dialog" role="dialog" aria-modal="true" aria-labelledby="stepUpTitle">
                    <h2 id="stepUpTitle">Verify Again</h2>
                    <p id="stepUpPrompt">This action needs recent MFA. Enter an authenticator app code or recovery code.</p>
                    <form id="stepUpModalForm">
                        <input type="text" id="stepUpModalCode" placeholder="000000 or recovery code" required />
                        <div class="actions">
                            <button type="button" class="secondary" id="stepUpCancel">Cancel</button>
                            <button type="submit">Verify</button>
                        </div>
                    </form>
                    <div id="stepUpSetup" class="step-up-setup">
                        <p>Set up an authenticator app before continuing.</p>
                        <div class="actions">
                            <button type="button" class="secondary" id="stepUpSetupCancel">Cancel</button>
                            <button type="button" id="stepUpSetupButton">Set Up Authenticator</button>
                        </div>
                    </div>
                    <div id="stepUpModalResult"></div>
                </div>
            `;
            document.body.appendChild(modal);
            return modal;
        }

        function promptForStepUp() {
            if (ashlarStepUpPromise) return ashlarStepUpPromise;

            ashlarStepUpPromise = new Promise((resolve, reject) => {
                const modal = ensureStepUpModal();
                const form = document.getElementById('stepUpModalForm');
                const codeInput = document.getElementById('stepUpModalCode');
                const result = document.getElementById('stepUpModalResult');
                const cancel = document.getElementById('stepUpCancel');
                const prompt = document.getElementById('stepUpPrompt');
                const setup = document.getElementById('stepUpSetup');
                const setupCancel = document.getElementById('stepUpSetupCancel');
                const setupButton = document.getElementById('stepUpSetupButton');
                const button = form.querySelector('button[type="submit"]');

                const close = () => {
                    modal.classList.remove('active');
                    document.body.classList.remove('step-up-modal-open');
                    form.onsubmit = null;
                    cancel.onclick = null;
                    setupCancel.onclick = null;
                    setupButton.onclick = null;
                    ashlarStepUpPromise = null;
                };

                result.innerText = '';
                result.style.color = '';
                prompt.innerText = 'This action needs recent MFA. Enter an authenticator app code or recovery code.';
                form.style.display = '';
                setup.style.display = 'none';
                codeInput.value = '';
                button.disabled = false;
                modal.classList.add('active');
                document.body.classList.add('step-up-modal-open');

                cancel.onclick = () => {
                    close();
                    reject(new Error('step_up_cancelled'));
                };
                setupCancel.onclick = cancel.onclick;
                setupButton.onclick = () => {
                    const setupUrl = setupButton.dataset.setupUrl || '/account#security';
                    if (location.pathname === '/account') {
                        close();
                        reject(new Error('step_up_setup_required'));
                        history.replaceState(null, '', setupUrl);
                        if (typeof window.switchTab === 'function') {
                            window.switchTab('security');
                        }
                        return;
                    }

                    location.href = setupUrl;
                    reject(new Error('step_up_setup_required'));
                };

                form.onsubmit = async (event) => {
                    event.preventDefault();
                    button.disabled = true;
                    result.style.color = '';
                    result.innerText = 'Verifying...';
                    try {
                        const response = await fetch('/api/account/security/verify', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ code: codeInput.value })
                        });
                        const body = response.headers.get('Content-Type')?.includes('application/json') ? await response.json() : {};
                        if (response.ok) {
                            close();
                            resolve();
                            return;
                        }

                        result.style.color = '#dc2626';
                        result.innerText = formatSampleError(body.error, 'Verification failed.');
                        button.disabled = false;
                    } catch (err) {
                        result.style.color = '#dc2626';
                        result.innerText = 'Connection error.';
                        button.disabled = false;
                    }
                };

                fetch('/api/account/security/step-up-options')
                    .then(response => response.ok ? response.json() : null)
                    .then(options => {
                        if (options && !options.canUseCode) {
                            prompt.innerText = 'This action needs recent MFA, but this account does not have an authenticator app or recovery codes yet.';
                            form.style.display = 'none';
                            setup.style.display = 'block';
                            setupButton.dataset.setupUrl = options.setupUrl || '/account#security';
                            setupButton.focus();
                            return;
                        }

                        codeInput.focus();
                    })
                    .catch(() => codeInput.focus());
            });

            return ashlarStepUpPromise;
        }

        async function ashlarFetchWithStepUp(url, options) {
            const first = await fetch(url, options);
            if (first.status !== 403 || first.headers.get('X-Ashlar-Step-Up') !== 'required') return first;

            try {
                await promptForStepUp();
            } catch (err) {
                return first;
            }

            return await fetch(url, options);
        }

        function base64UrlToBuffer(value) {
            const base64 = String(value).replace(/-/g, '+').replace(/_/g, '/');
            const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
            const binary = atob(padded);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            return bytes.buffer;
        }

        function bufferToBase64Url(buffer) {
            const bytes = new Uint8Array(buffer || new ArrayBuffer(0));
            let binary = '';
            bytes.forEach(b => binary += String.fromCharCode(b));
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        }

        function prepareCredentialCreationOptions(options) {
            const publicKey = structuredClone(options);
            publicKey.challenge = base64UrlToBuffer(publicKey.challenge);
            publicKey.user.id = base64UrlToBuffer(publicKey.user.id);
            publicKey.excludeCredentials = (publicKey.excludeCredentials || []).map(c => ({ ...c, id: base64UrlToBuffer(c.id) }));
            return { publicKey };
        }

        function prepareCredentialRequestOptions(options) {
            const publicKey = structuredClone(options);
            publicKey.challenge = base64UrlToBuffer(publicKey.challenge);
            publicKey.allowCredentials = (publicKey.allowCredentials || []).map(c => ({ ...c, id: base64UrlToBuffer(c.id) }));
            return { publicKey };
        }

        function serializeCreatedCredential(credential) {
            return {
                id: credential.id,
                rawId: bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
                    attestationObject: bufferToBase64Url(credential.response.attestationObject),
                    transports: typeof credential.response.getTransports === 'function' ? credential.response.getTransports() : []
                }
            };
        }

        function serializeAssertionCredential(credential) {
            return {
                id: credential.id,
                rawId: bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
                    authenticatorData: bufferToBase64Url(credential.response.authenticatorData),
                    signature: bufferToBase64Url(credential.response.signature),
                    userHandle: credential.response.userHandle ? bufferToBase64Url(credential.response.userHandle) : null
                }
            };
        }

        function passkeysAvailable() {
            return window.PublicKeyCredential && navigator.credentials && window.isSecureContext;
        }

        function handleMfaRequired(handshakeToken, requiredFactors) {
            const factors = (requiredFactors || []).map(f => String(f).toLowerCase());
            const canUsePasskey = factors.includes('passkey');
            document.querySelector('.card').innerHTML = '<h1>Additional Verification Required</h1><p>Please enter an authenticator app code or recovery code below.</p><form id="mfaForm"><input type="text" id="mfaCode" placeholder="000000 or XXXX-XXXX-XXXX" required /><button type="submit">Verify</button></form>' + (canUsePasskey ? '<button id="passkeyMfaButton" class="secondary" style="margin-top: 1rem;">Use Passkey</button>' : '') + '<div id="mfaResult"></div>';
            document.getElementById('mfaForm').onsubmit = async (mfaE) => {
                mfaE.preventDefault();
                const mfaBtn = mfaE.target.querySelector('button');
                const mfaRes = document.getElementById('mfaResult');
                mfaBtn.disabled = true;
                try {
                    const mfaResp = await fetch('/api/mfa/verify', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ handshakeToken: handshakeToken, code: document.getElementById('mfaCode').value })
                    });
                    const mfaResult = await mfaResp.json();
                    if (mfaResp.ok) {
                        location.href = '/';
                    } else {
                        mfaRes.style.color = '#dc2626';
                        mfaRes.innerText = formatSampleError(mfaResult.error, 'Invalid code.');
                        mfaBtn.disabled = false;
                    }
                } catch (err) { mfaRes.innerText = 'Error connecting.'; mfaBtn.disabled = false; }
            };
            const passkeyMfaButton = document.getElementById('passkeyMfaButton');
            if (!passkeyMfaButton) return;

            passkeyMfaButton.onclick = async (e) => {
                const btn = e.target;
                const mfaRes = document.getElementById('mfaResult');
                if (!passkeysAvailable()) {
                    mfaRes.style.color = '#dc2626';
                    mfaRes.innerText = 'Passkeys require a secure browser context.';
                    return;
                }

                btn.disabled = true;
                mfaRes.style.color = '';
                mfaRes.innerText = 'Waiting for passkey...';
                try {
                    const optionsResponse = await fetch('/api/passkeys/factor/options', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ handshakeToken: handshakeToken, factorType: 'passkey' })
                    });
                    const optionsResult = await optionsResponse.json();
                    if (!optionsResponse.ok) {
                        mfaRes.style.color = '#dc2626';
                        mfaRes.innerText = formatSampleError(optionsResult.error, 'Passkey challenge failed.');
                        btn.disabled = false;
                        return;
                    }

                    const credential = await navigator.credentials.get(prepareCredentialRequestOptions(optionsResult.options));
                    const completeResponse = await fetch('/api/passkeys/factor/complete', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ challengeId: optionsResult.challengeId, assertionResponse: serializeAssertionCredential(credential), handshakeToken: handshakeToken, factorType: 'passkey' })
                    });
                    const completeResult = await completeResponse.json();
                    if (completeResponse.ok && completeResult.status === 'signed_in') {
                        location.href = '/';
                    } else if (completeResponse.ok && completeResult.status === 'mfa_required') {
                        handleMfaRequired(completeResult.handshakeToken, completeResult.requiredFactors);
                    } else {
                        mfaRes.style.color = '#dc2626';
                        mfaRes.innerText = formatSampleError(completeResult.error, 'Passkey verification failed.');
                        btn.disabled = false;
                    }
                } catch (err) {
                    mfaRes.style.color = '#dc2626';
                    mfaRes.innerText = 'Passkey verification was cancelled or failed.';
                    btn.disabled = false;
                }
            };
        }
    """;

    private const string DashboardScripts = $$"""
        <script>
            {{SharedScripts}}

            setupForm('bootstrapForm', '/api/bootstrap/invitations', 'POST',
                f => ({ email: f.querySelector('#bootstrapEmail').value, userName: f.querySelector('#bootstrapUsername').value }),
                (r, div) => {
                    div.innerHTML = '<p class="badge badge-success" style="margin-bottom: 1rem;">Bootstrap complete!</p><button onclick="location.href=\'/\'">Go to Dashboard</button>';
                }
            );

            setupForm('signInForm', '/api/auth/magic-link/request', 'POST',
                f => ({ email: f.querySelector('#signInEmail').value }),
                (r, div) => { div.innerHTML = '<p class="badge badge-success">Magic link sent!</p>'; }
            );

            const passkeySignInButton = document.getElementById('passkeySignInButton');
            if (passkeySignInButton) {
                passkeySignInButton.disabled = !passkeysAvailable();
                document.getElementById('passkeyUnavailable').classList.toggle('hidden', passkeysAvailable());
                passkeySignInButton.onclick = async (e) => {
                    const btn = e.target;
                    const resDiv = document.getElementById('passkeySignInResult');
                    btn.disabled = true;
                    resDiv.style.color = '';
                    resDiv.innerText = 'Waiting for passkey...';
                    try {
                        const optionsResponse = await fetch('/api/passkeys/authentication/options', { method: 'POST' });
                        const optionsResult = await optionsResponse.json();
                        if (!optionsResponse.ok) {
                            resDiv.style.color = '#dc2626';
                            resDiv.innerText = formatSampleError(optionsResult.error, 'Passkey challenge failed.');
                            btn.disabled = false;
                            return;
                        }

                        const credential = await navigator.credentials.get(prepareCredentialRequestOptions(optionsResult.options));
                        const completeResponse = await fetch('/api/passkeys/authentication/complete', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ challengeId: optionsResult.challengeId, assertionResponse: serializeAssertionCredential(credential) })
                        });
                        const completeResult = await completeResponse.json();
                        if (completeResponse.ok && completeResult.status === 'signed_in') {
                            location.href = '/';
                        } else if (completeResponse.ok && completeResult.status === 'mfa_required') {
                            handleMfaRequired(completeResult.handshakeToken, completeResult.requiredFactors);
                        } else {
                            resDiv.style.color = '#dc2626';
                            resDiv.innerText = formatSampleError(completeResult.error, 'Passkey sign-in failed.');
                            btn.disabled = false;
                        }
                    } catch (err) {
                        resDiv.style.color = '#dc2626';
                        resDiv.innerText = 'Passkey sign-in was cancelled or failed.';
                        btn.disabled = false;
                    }
                };
            }
        </script>
    """;

    public static IResult RenderDashboard(BootstrapStatus status, bool isAuthenticated, string? userName, bool isAdmin, List<(string Id, string Name, bool HasAccess)> projects)
    {
        var bootstrapSection = RenderBootstrapSection(status, isAuthenticated);
        var authSection = RenderAuthSection(status, isAuthenticated, userName);
        var projectSection = isAuthenticated ? RenderProjectSection(projects) : "";

        var navLinks = "";
        if (isAuthenticated)
        {
            navLinks = $"""
                <a href="/">Dashboard</a>
                <a href="/account">Account</a>
                {(isAdmin ? AdminLink : "")}
                <form action="/api/auth/logout" method="POST" style="display: inline;"><button type="submit" class="link-btn">Sign Out</button></form>
            """;
        }

        var content = $"""
            {bootstrapSection}
            {authSection}
            {projectSection}
            {DashboardScripts}
        """;

        return LandingPages.Layout("Dashboard", content, navLinks);
    }

    private static string RenderBootstrapSection(BootstrapStatus status, bool isAuthenticated)
    {
        if (status != BootstrapStatus.Uninitialized || isAuthenticated)
        {
            return "";
        }

        return """
            <div class="card">
                <h2>Bootstrap Required</h2>
                <div class="status-box">
                    The system is currently <strong>uninitialized</strong>. Create the first administrative account to get started.
                </div>
                <form id="bootstrapForm">
                    <input type="email" id="bootstrapEmail" placeholder="admin@example.com" required />
                    <input type="text" id="bootstrapUsername" placeholder="Admin Username" required />
                    <button type="submit">Bootstrap System</button>
                </form>
                <div id="bootstrapFormResult"></div>
            </div>
        """;
    }

    private static string RenderAuthSection(BootstrapStatus status, bool isAuthenticated, string? userName)
    {
        if (isAuthenticated)
        {
            var welcome = string.IsNullOrWhiteSpace(userName) ? "Welcome back!" : $"Welcome back, {System.Net.WebUtility.HtmlEncode(userName)}!";

            return $"""
                <div style="margin-bottom: 2rem;">
                    <h2 style="margin: 0; font-size: 1.5rem;">{welcome}</h2>
                </div>
            """;
        }

        if (status != BootstrapStatus.Initialized)
        {
            return "";
        }

        return """
            <div class="card">
                <h2>Sign In</h2>
                <p>Welcome to Ashlar. Enter your email to receive a magic link for signing in.</p>
                <form id="signInForm">
                    <input type="email" id="signInEmail" placeholder="your@email.com" required />
                    <button type="submit">Send Magic Link</button>
                </form>
                <div id="signInFormResult"></div>
                <hr style="margin: 2rem 0; border: 0; border-top: 1px solid #e5e7eb;" />
                <button id="passkeySignInButton" class="secondary" type="button">Sign In With Passkey</button>
                <p id="passkeyUnavailable" class="hidden" style="color: #6b7280; margin-bottom: 0;">Passkeys require HTTPS or localhost in a browser that supports WebAuthn.</p>
                <div id="passkeySignInResult"></div>
            </div>
        """;
    }

    private static string RenderProjectSection(List<(string Id, string Name, bool HasAccess)> projects)
    {
        var projectItems = projects.Select(p =>
        {
            var badge = p.HasAccess ? "<span class=\"badge badge-success\">Manager</span>" : "<span class=\"badge\">No Access</span>";
            var button = $"""<button class="secondary" onclick="location.href='/projects/{System.Web.HttpUtility.JavaScriptStringEncode(System.Net.WebUtility.UrlEncode(p.Id))}'" {(p.HasAccess ? "" : "disabled")} style="margin-top: 0.5rem; height: 2.5rem;">Manage {System.Net.WebUtility.HtmlEncode(p.Name)}</button>""";

            return $"""
                <div style="border-bottom: 1px solid #e5e7eb; padding: 1rem 0;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span>Project: <strong>{System.Net.WebUtility.HtmlEncode(p.Name)}</strong></span>
                        {badge}
                    </div>
                    {button}
                </div>
            """;
        });

        return $"""
            <div class="card">
                <h2>Your Projects</h2>
                <div class="status-box" style="margin-bottom: 0;">
                    {(projects.Count > 0 ? string.Join("", projectItems) : "No projects found.")}
                </div>
            </div>
        """;
    }

    private static AccountSecurityDisplayState CreateSecurityDisplay(UserSecurityPosture posture)
    {
        var hasAdditionalVerification = posture.AdditionalVerificationFactors.Any(f => f.IsConfigured);
        var isReadyForAdditionalVerification = posture.Policy.IsReadyForAdditionalVerification;
        var protectedActionStatus = GetProtectedActionStatus(hasAdditionalVerification, isReadyForAdditionalVerification);

        return new AccountSecurityDisplayState(
            HasTotp: HasConfiguredFactor(posture, AuthenticationFactorTypes.Totp),
            HasRecoveryCodes: HasConfiguredFactor(posture, AuthenticationFactorTypes.RecoveryCode),
            HasPasskeys: posture.CredentialInventory.Any(c => c.Provider.Type == ProviderType.Passkey),
            SignInMethods: FormatSignInMethods(posture),
            ProtectedActionStatus: protectedActionStatus,
            MissingVerification: FormatMissingVerification(posture, hasAdditionalVerification),
            VerificationStatus: FormatVerificationStatus(posture, hasAdditionalVerification));
    }

    private static string GetProtectedActionStatus(bool hasAdditionalVerification, bool isReadyForAdditionalVerification)
    {
        if (hasAdditionalVerification && isReadyForAdditionalVerification)
        {
            return "Available";
        }

        return "Blocked until setup";
    }

    private static bool HasConfiguredFactor(UserSecurityPosture posture, string factorType)
    {
        return posture.AdditionalVerificationFactors.Any(factor =>
            string.Equals(factor.FactorType, factorType, StringComparison.OrdinalIgnoreCase) && factor.IsConfigured);
    }

    private static string FormatSignInMethods(UserSecurityPosture posture)
    {
        var methods = string.Join(", ", posture.PrimaryCredentials.Select(c => c.DisplayName).Distinct(StringComparer.Ordinal));
        return methods.Length > 0 ? methods : "None";
    }

    private static string FormatMissingVerification(UserSecurityPosture posture, bool hasAdditionalVerification)
    {
        if (hasAdditionalVerification && posture.Policy.IsReadyForAdditionalVerification)
        {
            return "None";
        }

        if (posture.Policy.MissingRequiredFactorDisplayNames.Count > 0)
        {
            return string.Join(" or ", posture.Policy.MissingRequiredFactorDisplayNames);
        }

        return "Authenticator app or passkey";
    }

    private static string FormatVerificationStatus(UserSecurityPosture posture, bool hasAdditionalVerification)
    {
        if (hasAdditionalVerification)
        {
            return "<span class=\"badge badge-success\">Configured</span>";
        }

        if (posture.Policy.IsAdditionalVerificationRequired)
        {
            return "<span class=\"badge badge-warning\">Setup required</span>";
        }

        return "<span class=\"badge\">Not configured</span>";
    }

    private static string FormatEmailVerificationBadge(UserSecurityPosture posture)
    {
        if (posture.IsEmailVerified)
        {
            return "<span class=\"badge badge-success\">Verified</span>";
        }

        return "<span class=\"badge badge-warning\">Unverified</span>";
    }

    private static string RenderVerifyEmailForm(UserSecurityPosture posture)
    {
        if (posture.IsEmailVerified)
        {
            return "";
        }

        return """
            <hr style="margin: 2rem 0; border: 0; border-top: 1px solid #e5e7eb;" />
            <h3>Verify Email</h3>
            <p>Your email address is not yet verified.</p>
            <form id="verifyEmailForm">
                <button type="submit" class="secondary">Resend Verification Code</button>
            </form>
            <div id="verifyEmailFormResult"></div>
        """;
    }

    private static string FormatEnabledBadge(bool isEnabled)
    {
        if (isEnabled)
        {
            return "<span class=\"badge badge-success\">Enabled</span>";
        }

        return "<span class=\"badge\">Not set</span>";
    }

    private static string FormatRegisteredBadge(bool isRegistered)
    {
        if (isRegistered)
        {
            return "<span class=\"badge badge-success\">Registered</span>";
        }

        return "<span class=\"badge\">None</span>";
    }

    private static string FormatGeneratedBadge(bool isGenerated)
    {
        if (isGenerated)
        {
            return "<span class=\"badge badge-success\">Generated</span>";
        }

        return "<span class=\"badge\">None</span>";
    }

    private static string RenderMfaActions(AccountSecurityDisplayState securityDisplay)
    {
        if (!securityDisplay.HasTotp)
        {
            return """
                <div style="margin-top: 1rem;">
                    <button onclick="location.href='/account/mfa/enroll'" style="height: 2.5rem;">Enable Authenticator App</button>
                </div>
              """;
        }

        var recoveryCodesButtonText = securityDisplay.HasRecoveryCodes ? "Regenerate Recovery Codes" : "Generate Recovery Codes";

        return $"""
            <div class="grid" style="margin-top: 1rem;">
                <button id="generateBtn" class="secondary" style="height: 2.5rem;">{recoveryCodesButtonText}</button>
                <button id="resetMfaBtn" class="secondary danger" style="height: 2.5rem;">Reset Authenticator App</button>
            </div>
            <div id="codesResult" style="margin-top: 1.5rem;"></div>
          """;
    }

    private sealed record AccountSecurityDisplayState(
        bool HasTotp,
        bool HasRecoveryCodes,
        bool HasPasskeys,
        string SignInMethods,
        string ProtectedActionStatus,
        string MissingVerification,
        string VerificationStatus);

    public static IResult RenderAccountSettings(string userEmail, string? userName, UserSecurityPosture posture, bool isAdmin)
    {
        var verifiedBadge = FormatEmailVerificationBadge(posture);
        var verifyForm = RenderVerifyEmailForm(posture);
        var securityDisplay = CreateSecurityDisplay(posture);
        var totpStatus = FormatEnabledBadge(securityDisplay.HasTotp);
        var passkeyStatus = FormatRegisteredBadge(securityDisplay.HasPasskeys);
        var recoveryStatus = FormatGeneratedBadge(securityDisplay.HasRecoveryCodes);
        var mfaActions = RenderMfaActions(securityDisplay);

        var navLinks = $"""
            <a href="/">Dashboard</a>
            <a href="/account">Account</a>
            {(isAdmin ? AdminLink : "")}
            <form action="/api/auth/logout" method="POST" style="display: inline;"><button type="submit" class="link-btn">Sign Out</button></form>
        """;

        return LandingPages.Layout("Account Settings", $$"""
            <style>
                .tabs { display: flex; border-bottom: 2px solid #e5e7eb; margin-bottom: 2rem; gap: 2rem; }
                .tab-btn { background: none; border: none; border-bottom: 2px solid transparent; padding: 0.75rem 0.5rem; font-weight: 600; color: #6b7280; cursor: pointer; border-radius: 0; margin-bottom: -2px; width: auto; font-size: 1rem; transition: color 0.2s; }
                .tab-btn:hover { color: #2563eb; background: none; box-shadow: none; }
                .tab-btn.active { color: #2563eb; border-bottom-color: #2563eb; }
                .tab-pane { display: none; }
                .tab-pane.active { display: block; }
            </style>

            <div class="card">
                <h1>Account & Security</h1>
                <div class="status-box" style="margin-bottom: 2rem;">
                    <strong>Email:</strong> {{System.Net.WebUtility.HtmlEncode(userEmail)}} {{verifiedBadge}}<br/>
                    <strong>Name:</strong> <span id="displayName">{{System.Net.WebUtility.HtmlEncode(userName ?? "Not set")}}</span>
                </div>

                <div class="tabs">
                    <button class="tab-btn active" onclick="switchTab('profile')">Profile</button>
                    <button class="tab-btn" onclick="switchTab('security')">Security</button>
                </div>

                <div id="profile" class="tab-pane active">
                    <h3>Display Name</h3>
                    <p>Update your display name.</p>
                    <form id="profileForm">
                        <div style="display: flex; gap: 0.5rem;">
                            <input type="text" id="newName" value="{{System.Net.WebUtility.HtmlEncode(userName ?? "")}}" placeholder="Your Name" required style="margin: 0; flex: 1;" />
                            <button type="submit" style="width: auto; height: 3rem;">Update Name</button>
                        </div>
                    </form>
                    <div id="profileFormResult"></div>

                    <hr style="margin: 2.5rem 0; border: 0; border-top: 1px solid #e5e7eb;" />

                    <h3>Email Address</h3>
                    <p>Update your email address.</p>
                    <form id="changeEmailForm">
                        <div style="display: flex; gap: 0.5rem;">
                            <input type="email" id="newEmail" placeholder="new-email@example.com" required style="margin: 0; flex: 1;" />
                            <button type="submit" style="width: auto; height: 3rem;">Change Email</button>
                        </div>
                    </form>
                    <div id="changeEmailFormResult"></div>
                    {{verifyForm}}
                </div>

                <div id="security" class="tab-pane">
                    <h3>Sign-In Verification</h3>
                    <div class="status-box" style="margin-top: 1rem;">
                        <strong>Sign-in methods:</strong> {{System.Net.WebUtility.HtmlEncode(securityDisplay.SignInMethods)}}<br/>
                        <strong>Protected actions:</strong> {{securityDisplay.ProtectedActionStatus}}<br/>
                        <strong>Missing setup:</strong> {{System.Net.WebUtility.HtmlEncode(securityDisplay.MissingVerification)}}
                    </div>
                    <div class="status-box" style="margin-top: 1rem;">
                        <div style="display: flex; justify-content: space-between; align-items: center; gap: 1rem;">
                            <strong>Additional verification</strong>
                            {{securityDisplay.VerificationStatus}}
                        </div>
                        <div style="display: grid; gap: 0.5rem; margin-top: 1rem;">
                            <div style="display: flex; justify-content: space-between; gap: 1rem;"><span>Authenticator app</span>{{totpStatus}}</div>
                            <div style="display: flex; justify-content: space-between; gap: 1rem;"><span>Passkeys</span>{{passkeyStatus}}</div>
                            <div style="display: flex; justify-content: space-between; gap: 1rem;"><span>Recovery codes</span>{{recoveryStatus}}</div>
                        </div>
                    </div>
                    {{mfaActions}}

                    <hr style="margin: 2.5rem 0; border: 0; border-top: 1px solid #e5e7eb;" />

                    <h3>Passkeys</h3>
                    <p>Register and manage passkeys for this account.</p>
                    <div style="display: flex; gap: 0.5rem;">
                        <input type="text" id="passkeyDisplayName" placeholder="Laptop, phone, or security key" style="margin: 0; flex: 1;" />
                        <button id="registerPasskeyBtn" type="button" style="width: auto; height: 3rem;">Add Passkey</button>
                    </div>
                    <p id="passkeySettingsUnavailable" class="hidden" style="color: #6b7280;">Passkeys require HTTPS or localhost in a browser that supports WebAuthn.</p>
                    <div id="passkeyResult"></div>
                    <div id="passkeyList" style="margin-top: 1rem;">
                        <div class="status-box">Loading passkeys...</div>
                    </div>

                    <hr style="margin: 2.5rem 0; border: 0; border-top: 1px solid #e5e7eb;" />

                    <h3>Active Sessions</h3>
                    <p>Manage devices and browsers currently signed into your account.</p>
                    <div id="sessionList">
                        <div class="status-box">Loading active sessions...</div>
                    </div>
                    <button id="revokeOthersBtn" class="secondary danger" style="margin-top: 1.5rem; height: 2.5rem;">Revoke All Other Sessions</button>
                </div>
            </div>
            <script>
                {{SharedScripts}}

                window.switchTab = (tabId) => {
                    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
                    document.querySelector(`[onclick="switchTab('${tabId}')"]`).classList.add('active');
                    document.getElementById(tabId).classList.add('active');
                };

                if (location.hash === '#security') {
                    switchTab('security');
                }

                setupForm('profileForm', '/api/account/profile', 'POST',
                    f => ({ name: f.querySelector('#newName').value }),
                    (r, div) => { 
                        div.innerHTML = '<p class="badge badge-success">Profile updated!</p>';
                        document.getElementById('displayName').innerText = r.name || 'Not set';
                    }
                );

                setupForm('changeEmailForm', '/api/account/change-email/request', 'POST',
                    f => ({ newEmail: f.querySelector('#newEmail').value }),
                    (r, div) => { div.innerHTML = '<p class="badge badge-success">Confirmation link sent to new address!</p>'; }
                );

                setupForm('verifyEmailForm', '/api/account/verify-email/request', 'POST',
                    f => ({}),
                    (r, div) => { div.innerHTML = '<p class="badge badge-success">Verification code sent! <a href="/account/verify-email">Go to verification page</a></p>'; }
                );

                if (document.getElementById('generateBtn')) {
                    document.getElementById('generateBtn').onclick = async (e) => {
                        const btn = e.target;
                        const resDiv = document.getElementById('codesResult');
                        btn.disabled = true;
                        resDiv.innerText = 'Generating...';
                        try {
                            const response = await ashlarFetchWithStepUp('/api/mfa/recovery-codes', { method: 'POST' });
                            const result = await response.json();
                            if (response.ok) {
                                let html = '<p class="badge badge-warning">Write these down! They will not be shown again.</p><div class="grid" style="margin-top: 1rem;">';
                                result.codes.forEach(c => html += '<code>' + c + '</code>');
                                html += '</div>';
                                resDiv.innerHTML = html;
                                btn.innerText = 'Regenerate Recovery Codes';
                                btn.disabled = false;
                            } else { resDiv.innerText = 'Error generating codes.'; btn.disabled = false; }
                        } catch (err) { resDiv.innerText = 'Connection error.'; btn.disabled = false; }
                    };
                }

                if (document.getElementById('resetMfaBtn')) {
                    document.getElementById('resetMfaBtn').onclick = async (e) => {
                        if (!confirm('Are you sure you want to reset your authenticator app? You will need to enroll again.')) return;
                        const response = await ashlarFetchWithStepUp('/api/mfa/totp/reset', { method: 'POST' });
                        if (response.ok) { location.reload(); } else { alert('Reset failed.'); }
                    };
                }

                const passkeyResult = document.getElementById('passkeyResult');
                const passkeyList = document.getElementById('passkeyList');
                const registerPasskeyBtn = document.getElementById('registerPasskeyBtn');
                const passkeyNameInput = document.getElementById('passkeyDisplayName');

                function setPasskeyResult(message, isError) {
                    passkeyResult.style.color = isError ? '#dc2626' : '';
                    passkeyResult.innerText = message;
                }

                async function loadPasskeys() {
                    const response = await fetch('/api/passkeys');
                    if (!response.ok || !response.headers.get('Content-Type')?.includes('application/json')) {
                        passkeyList.innerHTML = '<div class="status-box">Unable to load passkeys.</div>';
                        return;
                    }

                    const passkeys = await response.json();
                    passkeyList.innerHTML = '';
                    if (passkeys.length === 0) {
                        passkeyList.innerHTML = '<div class="status-box">No passkeys registered.</div>';
                        return;
                    }

                    passkeys.forEach(p => {
                        const item = document.createElement('div');
                        item.className = 'status-box';
                        item.style.display = 'grid';
                        item.style.gridTemplateColumns = '1fr auto';
                        item.style.gap = '1rem';
                        item.style.alignItems = 'center';

                        const info = document.createElement('div');
                        const title = document.createElement('strong');
                        title.innerText = p.displayName || 'Passkey';
                        const details = document.createElement('small');
                        const parts = [];
                        if (p.authenticatorAttachment) parts.push(p.authenticatorAttachment);
                        if (p.discoverable) parts.push('discoverable');
                        if (p.lastUsedAt) parts.push('Last used: ' + new Date(p.lastUsedAt).toLocaleString());
                        parts.push('Created: ' + new Date(p.createdAt).toLocaleString());
                        details.innerText = parts.join(' | ');
                        info.appendChild(title);
                        info.appendChild(document.createElement('br'));
                        info.appendChild(details);

                        const actions = document.createElement('div');
                        actions.style.display = 'flex';
                        actions.style.gap = '0.5rem';
                        const rename = document.createElement('button');
                        rename.className = 'secondary';
                        rename.type = 'button';
                        rename.style.cssText = 'width: auto; height: auto; padding: 0.25rem 0.75rem; font-size: 0.75rem; margin: 0;';
                        rename.innerText = 'Rename';
                        rename.onclick = () => renamePasskey(p.id, p.displayName || 'Passkey');
                        const revoke = document.createElement('button');
                        revoke.className = 'secondary danger';
                        revoke.type = 'button';
                        revoke.style.cssText = 'width: auto; height: auto; padding: 0.25rem 0.75rem; font-size: 0.75rem; margin: 0;';
                        revoke.innerText = 'Revoke';
                        revoke.onclick = () => revokePasskey(p.id);
                        actions.appendChild(rename);
                        actions.appendChild(revoke);

                        item.appendChild(info);
                        item.appendChild(actions);
                        passkeyList.appendChild(item);
                    });
                }

                async function renamePasskey(id, currentName) {
                    const displayName = prompt('Passkey name', currentName);
                    if (displayName === null) return;
                    const response = await ashlarFetchWithStepUp('/api/passkeys/' + id + '/rename', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ displayName })
                    });
                    if (response.ok) {
                        setPasskeyResult('Passkey renamed.', false);
                        await loadPasskeys();
                    } else {
                        const result = response.headers.get('Content-Type')?.includes('application/json') ? await response.json() : {};
                        setPasskeyResult(formatSampleError(result.error, 'Passkey rename failed.'), true);
                    }
                }

                async function revokePasskey(id) {
                    if (!confirm('Revoke this passkey?')) return;
                    const response = await ashlarFetchWithStepUp('/api/passkeys/' + id, { method: 'DELETE' });
                    if (response.ok) {
                        setPasskeyResult('Passkey revoked.', false);
                        await loadPasskeys();
                    } else {
                        const result = response.headers.get('Content-Type')?.includes('application/json') ? await response.json() : {};
                        setPasskeyResult(formatSampleError(result.error, 'Passkey revocation failed.'), true);
                    }
                }

                if (registerPasskeyBtn) {
                    registerPasskeyBtn.disabled = !passkeysAvailable();
                    document.getElementById('passkeySettingsUnavailable').classList.toggle('hidden', passkeysAvailable());
                    registerPasskeyBtn.onclick = async () => {
                        const displayName = passkeyNameInput.value || 'Passkey';
                        registerPasskeyBtn.disabled = true;
                        setPasskeyResult('Waiting for passkey registration...', false);
                        try {
                            const optionsResponse = await ashlarFetchWithStepUp('/api/passkeys/registration/options', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ displayName })
                            });
                            const optionsResult = await optionsResponse.json();
                            if (!optionsResponse.ok) {
                                setPasskeyResult(formatSampleError(optionsResult.error, 'Passkey challenge failed.'), true);
                                registerPasskeyBtn.disabled = false;
                                return;
                            }

                            const credential = await navigator.credentials.create(prepareCredentialCreationOptions(optionsResult.options));
                            const completeResponse = await ashlarFetchWithStepUp('/api/passkeys/registration/complete', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ challengeId: optionsResult.challengeId, credentialResponse: serializeCreatedCredential(credential), displayName })
                            });
                            const completeResult = completeResponse.headers.get('Content-Type')?.includes('application/json') ? await completeResponse.json() : {};
                            if (completeResponse.ok) {
                                passkeyNameInput.value = '';
                                setPasskeyResult('Passkey registered.', false);
                                await loadPasskeys();
                            } else {
                                setPasskeyResult(formatSampleError(completeResult.error, 'Passkey registration failed.'), true);
                            }
                        } catch (err) {
                            setPasskeyResult('Passkey registration was cancelled or failed.', true);
                        } finally {
                            registerPasskeyBtn.disabled = !passkeysAvailable();
                        }
                    };
                }

                function formatUA(ua) {
                    if (!ua) return 'Unknown Device';
                    const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome/.test(ua) ? 'Chrome' : /Firefox/.test(ua) ? 'Firefox' : /Safari/.test(ua) && !/Chrome/.test(ua) ? 'Safari' : 'Browser';
                    const os = /Windows/.test(ua) ? 'Windows' : /Mac OS/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : 'OS';
                    return browser + ' on ' + os;
                }

                const loadSessions = async () => {
                    const list = document.getElementById('sessionList');
                    const revokeOthersBtn = document.getElementById('revokeOthersBtn');
                    const showSessionError = () => {
                        list.innerHTML = '<div class="status-box">Unable to load active sessions.</div>';
                        revokeOthersBtn.classList.add('hidden');
                    };

                    const response = await fetch('/api/sessions');
                    if (!response.ok || !response.headers.get('Content-Type')?.includes('application/json')) {
                        showSessionError();
                        return;
                    }

                    let sessions = [];
                    try {
                        sessions = await response.json();
                    } catch (err) {
                        showSessionError();
                        return;
                    }

                    list.innerHTML = '';
                    if (sessions.length === 0) { list.innerHTML = '<div class="status-box">No active sessions found.</div>'; revokeOthersBtn.classList.add('hidden'); return; }

                    let otherSessionsCount = 0;
                    sessions.forEach(s => {
                        const item = document.createElement('div');
                        item.className = 'status-box';
                        item.style.display = 'flex';
                        item.style.justifyContent = 'space-between';
                        item.style.alignItems = 'center';
                        const displayIp = (s.ipAddress === '::1' || s.ipAddress === '127.0.0.1') ? 'Local Loopback' : (s.ipAddress || 'Unknown IP');
                        const sanitizedIp = displayIp.replace(/</g, '&lt;').replace(/>/g, '&gt;');
                        let info = '<div><strong>' + formatUA(s.userAgent) + '</strong><br/><small>' + sanitizedIp + ' | Created: ' + new Date(s.createdAt).toLocaleString() + '</small></div>';
                        let action = '';
                        if (s.isCurrent) { action = '<span class="badge badge-success">Current Session</span>'; } else { otherSessionsCount++; action = '<button class="secondary danger" style="width: auto; height: auto; padding: 0.25rem 0.75rem; font-size: 0.75rem; margin: 0;" onclick="revokeSession(\'' + s.id + '\')">Revoke</button>'; }
                        item.innerHTML = info + action;
                        list.appendChild(item);
                    });
                    if (otherSessionsCount > 0) { revokeOthersBtn.classList.remove('hidden'); } else { revokeOthersBtn.classList.add('hidden'); }
                };

                window.revokeSession = async (id) => {
                    if (!confirm('Revoke this session?')) return;
                    const response = await ashlarFetchWithStepUp('/api/sessions/' + id, { method: 'DELETE' });
                    if (response.ok) loadSessions();
                };

                document.getElementById('revokeOthersBtn').onclick = async (e) => {
                    if (!confirm('Revoke all other sessions?')) return;
                    const response = await ashlarFetchWithStepUp('/api/sessions/others', { method: 'DELETE' });
                    if (response.ok) loadSessions();
                };

                loadPasskeys();
                loadSessions();
            </script>
        """, navLinks);
    }

    public static IResult RenderAdminManage()
    {
        var navLinks = $"""
            <a href="/">Dashboard</a>
            <a href="/account">Account</a>
            {AdminLink}
            <form action="/api/auth/logout" method="POST" style="display: inline;"><button type="submit" class="link-btn">Sign Out</button></form>
        """;


        return LandingPages.Layout("Administration", $$"""
            <div class="card">
                <h1>Administration</h1>

                <h2>User Management</h2>
                <p>Invite new users to the application.</p>
                <form id="inviteForm">
                    <input type="email" id="inviteEmail" placeholder="invitee@example.com" required />
                    <button type="submit">Send Invitation</button>
                </form>
                <div id="inviteFormResult"></div>

                <hr style="margin: 2rem 0; border: 0; border-top: 1px solid #e5e7eb;" />

                <h2>Account Security</h2>
                <select id="securityUserId" style="width: 100%; padding: 0.75rem; margin-bottom: 1rem; border: 1px solid #d1d5db; border-radius: 4px;">
                    <option value="">Loading users...</option>
                </select>
                <div id="securityPosture" class="status-box">Select a user to view account security state.</div>
                <div class="grid" style="margin-top: 1rem;">
                    <button id="disableUserBtn" class="secondary danger hidden" style="height: 2.5rem;">Disable User</button>
                    <button id="reactivateUserBtn" class="secondary hidden" style="height: 2.5rem;">Reactivate User</button>
                    <button id="revokeUserSessionsBtn" class="secondary danger hidden" style="height: 2.5rem;">Revoke Sessions</button>
                    <button id="resetUserMfaBtn" class="secondary danger hidden" style="height: 2.5rem;">Reset Authenticator Factors</button>
                </div>
                <div id="securityActionResult"></div>

                <hr style="margin: 2rem 0; border: 0; border-top: 1px solid #e5e7eb;" />

                <h2>Project Management</h2>
                <p>Create new projects to manage scoped access.</p>
                <form id="projectForm">
                    <input type="text" id="projectId" placeholder="project-id (e.g. charlie)" required pattern="[a-z0-9-]+" />
                    <input type="text" id="projectName" placeholder="Project Name (e.g. Project Charlie)" required />
                    <button type="submit">Create Project</button>
                </form>
                <div id="projectFormResult"></div>

                <hr style="margin: 2rem 0; border: 0; border-top: 1px solid #e5e7eb;" />

                <h2>Permission Management</h2>
                <p>Grant "project.manage" permission to existing users.</p>
                <form id="grantForm">
                    <select id="grantUserId" required style="width: 100%; padding: 0.75rem; margin-bottom: 1rem; border: 1px solid #d1d5db; border-radius: 4px;">
                        <option value="">Loading users...</option>
                    </select>
                    <select id="grantProjectId" required style="width: 100%; padding: 0.75rem; margin-bottom: 1rem; border: 1px solid #d1d5db; border-radius: 4px;">
                        <option value="">Loading projects...</option>
                    </select>
                    <button type="submit">Grant Permission</button>
                </form>
                <div id="grantFormResult"></div>
            </div>
            <script>
                {{SharedScripts}}

                setupForm('projectForm', '/api/admin/projects', 'POST',

                    f => ({ id: f.querySelector('#projectId').value, name: f.querySelector('#projectName').value }),
                    (r, div) => {
                        div.innerHTML = '<p class="badge badge-success">Project created!</p>';
                        loadProjects(); // Refresh the list
                    }
                );

                setupForm('inviteForm', '/api/invitations', 'POST',

                    f => ({ email: f.querySelector('#inviteEmail').value }),
                    (r, div) => { div.innerHTML = '<p class="badge badge-success">Invitation sent!</p>'; }
                );

                setupForm('grantForm', f => '/api/projects/' + f.querySelector('#grantProjectId').value + '/grants', 'POST',

                    f => ({ userId: f.querySelector('#grantUserId').value }),
                    (r, div) => { div.innerHTML = '<p class="badge badge-success">Permission granted!</p>'; }
                );

                let adminUsers = [];

                const renderUserOptionText = u => (u.name || 'No Name') + ' (' + u.email + ')';

                const setSecurityActions = posture => {
                    document.getElementById('disableUserBtn').classList.toggle('hidden', !posture.isActive);
                    document.getElementById('reactivateUserBtn').classList.toggle('hidden', posture.isActive);
                    document.getElementById('revokeUserSessionsBtn').classList.toggle('hidden', posture.activeSessionCount < 1);
                    document.getElementById('resetUserMfaBtn').classList.toggle('hidden', !posture.isMfaConfigured);
                };

                const postureNames = items => [...new Set((items || []).map(item => item.displayName).filter(Boolean))].join(', ') || 'None';

                const loadSecurityPosture = async () => {
                    const userId = document.getElementById('securityUserId').value;
                    const div = document.getElementById('securityPosture');
                    if (!userId) {
                        div.innerText = 'Select a user to view account security state.';
                        setSecurityActions({ isActive: false, activeSessionCount: 0, isMfaConfigured: false });
                        return;
                    }

                    div.innerText = 'Loading...';
                    const response = await fetch('/api/admin/users/' + userId + '/security');
                    const result = await response.json();
                    if (!response.ok) {
                        div.style.color = '#dc2626';
                        div.innerText = formatSampleError(result.error, 'Unable to load account security state.');
                        setSecurityActions({ isActive: false, activeSessionCount: 0, isMfaConfigured: false });
                        return;
                    }

                    setSecurityActions(result);
                    div.style.color = '';
                    const credentials = postureNames(result.primaryCredentials);
                    const verification = postureNames(result.additionalVerificationFactors?.filter(f => f.isConfigured));
                    const hasAdditionalVerification = (result.additionalVerificationFactors || []).some(f => f.isConfigured);
                    const policy = result.policy || {};
                    const protectedActions = hasAdditionalVerification && policy.isReadyForAdditionalVerification ? 'Available' : 'Blocked until setup';
                    let missing = 'Authenticator app or passkey';
                    if (hasAdditionalVerification && policy.isReadyForAdditionalVerification) {
                        missing = 'None';
                    } else if (!policy.isReadyForAdditionalVerification && policy.missingRequiredFactorDisplayNames?.length) {
                        missing = policy.missingRequiredFactorDisplayNames.join(' or ');
                    }
                    div.replaceChildren();
                    [
                        ['Status', result.isActive ? 'Active' : 'Inactive'],
                        ['Email', result.isEmailVerified ? 'Verified' : 'Unverified'],
                        ['Sign-in methods', credentials],
                        ['Additional verification', verification],
                        ['Protected actions', protectedActions],
                        ['Missing setup', missing],
                        ['Active sessions', String(result.activeSessionCount)],
                        ['Recent security events', result.recentSecurityEventCount ?? 'Unavailable']
                    ].forEach(([label, value], index) => {
                        const strong = document.createElement('strong');
                        strong.textContent = label + ':';
                        div.appendChild(strong);
                        div.appendChild(document.createTextNode(' ' + value));
                        if (index < 7) div.appendChild(document.createElement('br'));
                    });
                };

                const runSecurityAction = async (path, label) => {
                    const userId = document.getElementById('securityUserId').value;
                    const div = document.getElementById('securityActionResult');
                    if (!userId) {
                        div.style.color = '#dc2626';
                        div.innerText = 'Select a user first.';
                        return;
                    }

                    div.style.color = '';
                    div.innerText = 'Processing...';
                    const response = await ashlarFetchWithStepUp('/api/admin/users/' + userId + path, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ reason: 'sample-admin' })
                    });
                    const result = response.headers.get('Content-Type')?.includes('application/json') ? await response.json() : {};
                    if (!response.ok) {
                        div.style.color = '#dc2626';
                        div.innerText = formatSampleError(result.error, label + ' failed.');
                        return;
                    }

                    div.innerHTML = '<p class="badge badge-success">' + label + ' complete.</p>';
                    await loadSecurityPosture();
                };

                document.getElementById('securityUserId').onchange = loadSecurityPosture;
                document.getElementById('disableUserBtn').onclick = () => runSecurityAction('/disable', 'Disable user');
                document.getElementById('reactivateUserBtn').onclick = () => runSecurityAction('/reactivate', 'Reactivate user');
                document.getElementById('revokeUserSessionsBtn').onclick = () => runSecurityAction('/sessions/revoke', 'Revoke sessions');
                document.getElementById('resetUserMfaBtn').onclick = () => runSecurityAction('/mfa/reset', 'Reset authenticator factors');

                fetch('/api/admin/users')
                    .then(r => r.json())
                    .then(users => {
                        adminUsers = users;
                        const grantSelect = document.getElementById('grantUserId');
                        const securitySelect = document.getElementById('securityUserId');
                        grantSelect.innerHTML = '';
                        securitySelect.innerHTML = '';
                        users.forEach(u => {
                            const grantOpt = document.createElement('option');
                            grantOpt.value = u.id;
                            grantOpt.innerText = renderUserOptionText(u);
                            grantSelect.appendChild(grantOpt);

                            const securityOpt = document.createElement('option');
                            securityOpt.value = u.id;
                            securityOpt.innerText = renderUserOptionText(u);
                            securitySelect.appendChild(securityOpt);
                        });
                        if (users.length === 0) {
                            grantSelect.innerHTML = '<option value="">No users found</option>';
                            securitySelect.innerHTML = '<option value="">No users found</option>';
                        } else {
                            loadSecurityPosture();
                        }
                    });

                const loadProjects = () => {
                    fetch('/api/admin/projects')
                        .then(r => r.json())
                        .then(projects => {
                            const select = document.getElementById('grantProjectId');
                            select.innerHTML = '';
                            projects.forEach(p => {
                                const opt = document.createElement('option');
                                opt.value = p.id;
                                opt.innerText = p.name + ' (' + p.id + ')';
                                select.appendChild(opt);
                            });
                        });
                };
                loadProjects();
            </script>
        """, navLinks);
    }

    public static IResult RenderMagicLinkCallback(string token)
    {
        return LandingPages.Render(
            "Sign In",
            "Click the button below to complete your sign-in to the application.",
            $$"""
            <button id="signInButton">Confirm Sign In</button>
            <div id="result"></div>
            <script>
                {{SharedScripts}}

                document.getElementById('signInButton').onclick = async (e) => {
                    const btn = e.target;
                    const resDiv = document.getElementById('result');
                    btn.disabled = true;
                    resDiv.innerText = 'Signing in...';

                    try {
                        const response = await fetch('/api/auth/magic-link/callback', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ t: '{{System.Web.HttpUtility.JavaScriptStringEncode(token)}}' })
                        });
                        const result = await response.json();
                        if (response.ok) {
                            if (result.status === 'mfa_required') {
                                handleMfaRequired(result.handshakeToken, result.requiredFactors);
                            } else {
                                location.href = '/';
                            }
                        } else {
                            resDiv.style.color = '#dc2626';
                            resDiv.innerText = formatSampleError(result.error, 'Sign-in failed.');
                            btn.disabled = false;
                        }
                    } catch (err) {
                        resDiv.style.color = '#dc2626';
                        resDiv.innerText = 'Connection error.';
                        btn.disabled = false;
                    }
                };
            </script>
            """);
    }

    public static IResult RenderInvitationAccept(string token)
    {
        return LandingPages.Render(
            "Join Ashlar",
            "You've been invited to join the application. Please enter your name to complete the process.",
            $$"""
            <form id="acceptForm">
                <input type="text" id="userName" placeholder="Your Name (Optional)" />
                <button type="submit">Accept Invitation</button>
            </form>
            <div id="result"></div>
            <script>
                {{SharedScripts}}

                document.getElementById('acceptForm').onsubmit = async (e) => {
                    e.preventDefault();
                    const btn = e.target.querySelector('button');
                    const resDiv = document.getElementById('result');
                    btn.disabled = true;
                    resDiv.innerText = 'Processing...';

                    try {
                        const response = await fetch('/api/invitations/accept', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                token: '{{System.Web.HttpUtility.JavaScriptStringEncode(token)}}',
                                userName: document.getElementById('userName').value
                            })
                        });
                        const result = await response.json();
                        if (response.ok) {
                            document.querySelector('.card').innerHTML = '<h1>Welcome!</h1><p>You have successfully joined the application. You are now signed in.</p><button onclick="location.href=\'/\'">Go to Dashboard</button>';
                        } else {
                            resDiv.style.color = '#dc2626';
                            resDiv.innerText = formatSampleError(result.error, 'Invitation could not be accepted.');
                            btn.disabled = false;
                        }
                    } catch (err) {
                        resDiv.style.color = '#dc2626';
                        resDiv.innerText = 'Connection error.';
                        btn.disabled = false;
                    }
                };
            </script>
            """);
    }

    public static IResult RenderEmailVerification(string? token, string? userId)
    {
        var tokenInput = string.IsNullOrEmpty(token)
            ? """<input type="text" id="verifyToken" placeholder="Enter verification code" required />"""
            : $"""<input type="hidden" id="verifyToken" value="{System.Net.WebUtility.HtmlEncode(token)}" />""";

        var instruction = string.IsNullOrEmpty(token)
            ? "Please enter the verification code sent to your email address."
            : "Click the button below to complete your email verification.";

        return LandingPages.Render(
            "Verify Email",
            instruction,
            $$"""
            <form id="verifyForm">
                <input type="hidden" id="userId" value="{{System.Net.WebUtility.HtmlEncode(userId ?? "")}}" />
                {{tokenInput}}
                <button type="submit">Verify Email</button>
            </form>
            <div id="result"></div>
            <script>
                document.getElementById('verifyForm').onsubmit = async (e) => {
                    e.preventDefault();
                    const btn = e.target.querySelector('button');
                    const resDiv = document.getElementById('result');
                    btn.disabled = true;
                    resDiv.innerText = 'Verifying...';
                    try {
                        const userId = document.getElementById('userId').value;
                        const url = '/api/account/verify-email/confirm' + (userId ? '?u=' + encodeURIComponent(userId) : '');
                        const response = await fetch(url, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ token: document.getElementById('verifyToken').value })
                        });
                        if (response.ok) {
                            resDiv.innerHTML = '<p class="badge badge-success">Email verified!</p><button onclick="location.href=\'/\'">Go to Dashboard</button>';
                            e.target.remove();
                        } else {
                            const result = await response.json();
                            resDiv.style.color = '#dc2626';
                            resDiv.innerText = result.error || 'Verification failed.';
                            btn.disabled = false;
                        }
                    } catch (err) { resDiv.innerText = 'Connection error.'; btn.disabled = false; }
                };
            </script>
            """);
    }

    public static IResult RenderEmailChangeConfirm(string? token, string? userId)
    {
        var tokenInput = string.IsNullOrEmpty(token)
            ? """<input type="text" id="confirmToken" placeholder="Enter confirmation code" required />"""
            : $"""<input type="hidden" id="confirmToken" value="{System.Net.WebUtility.HtmlEncode(token)}" />""";

        var instruction = string.IsNullOrEmpty(token)
            ? "Please enter the confirmation code sent to your new email address."
            : "Click the button below to confirm your new email address.";

        return LandingPages.Render(
            "Confirm Email Change",
            instruction,
            $$"""
            <form id="confirmForm">
                <input type="hidden" id="userId" value="{{System.Net.WebUtility.HtmlEncode(userId ?? "")}}" />
                {{tokenInput}}
                <button type="submit">Confirm Change</button>
            </form>
            <div id="result"></div>
            <script>
                document.getElementById('confirmForm').onsubmit = async (e) => {
                    e.preventDefault();
                    const btn = e.target.querySelector('button');
                    const resDiv = document.getElementById('result');
                    btn.disabled = true;
                    resDiv.innerText = 'Confirming...';
                    try {
                        const userId = document.getElementById('userId').value;
                        const url = '/api/account/change-email/confirm' + (userId ? '?u=' + encodeURIComponent(userId) : '');
                        const response = await fetch(url, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ token: document.getElementById('confirmToken').value })
                        });
                        if (response.ok) {
                            resDiv.innerHTML = '<p class="badge badge-success">Email changed successfully!</p><button onclick="location.href=\'/\'">Go to Dashboard</button>';
                            e.target.remove();
                        } else {
                            const result = await response.json();
                            resDiv.style.color = '#dc2626';
                            resDiv.innerText = result.error || 'Confirmation failed.';
                            btn.disabled = false;
                        }
                    } catch (err) { resDiv.innerText = 'Connection error.'; btn.disabled = false; }
                };
            </script>
            """);
    }

    public static IResult RenderMfaSetup(string sharedSecret, string authenticatorUri, bool isAdmin)
    {
        var navLinks = $"""
            <a href="/">Dashboard</a>
            <a href="/account">Account</a>
            {(isAdmin ? AdminLink : "")}
            <form action="/api/auth/logout" method="POST" style="display: inline;"><button type="submit" class="link-btn">Sign Out</button></form>
        """;

        return LandingPages.Layout("Authenticator App Setup", $$"""
            <div class="card">
                <h1>Setup Authenticator App</h1>
                <p>Scan the QR code with your authenticator app to enable code-based sign-in verification.</p>
                <div class="status-box" style="text-align: center;">
                    <div style="margin-bottom: 1rem; display: flex; justify-content: center;">
                        <canvas id="qr-code"></canvas>
                    </div>
                    <p>Shared Secret: <code>{{sharedSecret}}</code></p>
                </div>
                <form id="verifyForm">
                    <input type="hidden" id="secret" value="{{sharedSecret}}" />
                    <input type="text" id="code" placeholder="000000" required maxlength="6" />
                    <button type="submit">Verify & Enable Authenticator App</button>
                </form>
                <div id="result"></div>
            </div>
            <script src="https://cdn.jsdelivr.net/npm/qrcode@1.4.4/build/qrcode.min.js"></script>
            <script>
                window.addEventListener('load', () => {
                    if (typeof QRCode !== 'undefined') {
                        QRCode.toCanvas(document.getElementById('qr-code'), '{{System.Web.HttpUtility.JavaScriptStringEncode(authenticatorUri)}}', {
                            width: 200,
                            margin: 2,
                            color: { dark: '#111827', light: '#ffffff' }
                        }, function (error) {
                            if (error) console.error(error);
                        });
                    }
                });

                document.getElementById('verifyForm').onsubmit = async (e) => {
                    e.preventDefault();
                    const btn = e.target.querySelector('button');
                    const resDiv = document.getElementById('result');
                    btn.disabled = true;
                    try {
                        const response = await fetch('/api/mfa/totp/verify', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ sharedSecret: document.getElementById('secret').value, code: document.getElementById('code').value })
                        });
                        if (response.ok) {
                            location.href = '/account';
                        } else {
                            resDiv.style.color = '#dc2626';
                            resDiv.innerText = 'Invalid code. Please try again.';
                            btn.disabled = false;
                        }
                    } catch (err) { resDiv.innerText = 'Connection error.'; btn.disabled = false; }
                };
            </script>
        """, navLinks);
    }

    public static IResult RenderProjectManage(string projectId, bool isAdmin)
    {
        var navLinks = $"""
            <a href="/">Dashboard</a>
            <a href="/account">Account</a>
            {(isAdmin ? AdminLink : "")}
            <form action="/api/auth/logout" method="POST" style="display: inline;"><button type="submit" class="link-btn">Sign Out</button></form>
        """;

        return LandingPages.Layout("Project Management", $"""
            <div class="card">
                <h1>Manage Project: {System.Net.WebUtility.HtmlEncode(projectId)}</h1>
                <div class="badge badge-success">Manager</div>
                <p style="margin-top: 1rem;">You have 'project.manage' permission for project '{System.Net.WebUtility.HtmlEncode(projectId)}'.</p>
            </div>
        """, navLinks);
    }
}
