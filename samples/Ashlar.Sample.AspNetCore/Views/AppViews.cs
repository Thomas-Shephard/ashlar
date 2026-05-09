using Ashlar.Identity.Models;

namespace Ashlar.Sample.AspNetCore.Views;

internal static class AppViews
{
    private const string AdminSection = """
        <div class="card">
            <h2>Administration</h2>
            <p>You have administrative privileges.</p>
            <form id="inviteForm">
                <input type="email" id="inviteEmail" placeholder="invitee@example.com" required />
                <button type="submit">Send Invitation</button>
            </form>
            <div id="inviteFormResult"></div>
            <hr style="margin: 1.5rem 0; border: 0; border-top: 1px solid #e5e7eb;" />
            <p>Grant "project.manage" permission:</p>
            <form id="grantForm">
                <select id="grantUserId" required style="width: 100%; padding: 0.75rem; margin-bottom: 1rem; border: 1px solid #d1d5db; border-radius: 4px;">
                    <option value="">Loading users...</option>
                </select>
                <select id="grantProjectId" required style="width: 100%; padding: 0.75rem; margin-bottom: 1rem; border: 1px solid #d1d5db; border-radius: 4px;">
                    <option value="alpha">Project alpha</option>
                    <option value="beta">Project beta</option>
                </select>
                <button type="submit">Grant Permission</button>
            </form>
            <div id="grantFormResult"></div>
        </div>
    """;

    private const string DashboardScripts = """
        <script>
            const sampleErrorMessages = {
                handshake_not_found: 'Your sign-in session has expired. Request a new magic link and try again.',
                invalid_email: 'Enter a valid email address.',
                invalid_invitation: 'This invitation is invalid or has expired. Ask an administrator to send a new invitation.',
                invalid_mfa_code: 'That verification code was not accepted. Check the code and try again.',
                invalid_totp: 'That authenticator code was not accepted. Check the code and try again.',
                rate_limited: 'Too many attempts. Wait a moment, then try again.'
            };

            function formatSampleError(error, fallback) {
                if (!error) return fallback;
                if (sampleErrorMessages[error]) return sampleErrorMessages[error];
                const message = String(error)
                    .replace(/_/g, ' ')
                    .replace(/\b\w/g, c => c.toUpperCase());
                return /[.!?]$/.test(message) ? message : message + '.';
            }

            function setupForm(id, url, method, bodyMapper, successMapper) {
                const form = document.getElementById(id);
                if (!form) return;
                form.onsubmit = async (e) => {
                    e.preventDefault();
                    const btn = e.target.querySelector('button');
                    const resDiv = document.getElementById(id + 'Result');
                    btn.disabled = true;
                    resDiv.innerText = 'Processing...';
                    try {
                        let finalUrl = url;
                        if (id === 'grantForm') {
                           finalUrl = '/projects/' + e.target.querySelector('#grantProjectId').value + '/grants';
                        }

                        const response = await fetch(finalUrl, {
                            method: method,
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(bodyMapper(e.target))
                        });

                        let result = {};
                        if (response.status !== 204 && response.headers.get('Content-Type')?.includes('application/json')) {
                            result = await response.json();
                        }

                        if (response.ok) {
                            successMapper(result, resDiv);
                        } else {
                            resDiv.style.color = '#dc2626';
                            resDiv.innerText = formatSampleError(result.error, 'Request failed.');
                        }
                    } catch (err) {
                        resDiv.style.color = '#dc2626';
                        resDiv.innerText = 'Connection error.';
                    } finally {
                        btn.disabled = false;
                    }
                };
            }

            setupForm('bootstrapForm', '/bootstrap/invitations', 'POST',
                f => ({ email: f.querySelector('#bootstrapEmail').value, userName: f.querySelector('#bootstrapUsername').value }),
                (r, div) => {
                    div.innerHTML = '<p class="badge badge-success" style="margin-bottom: 1rem;">Bootstrap complete!</p><button onclick="location.href=\'/\'">Go to Dashboard</button>';
                }
            );

            setupForm('signInForm', '/auth/magic-link/request', 'POST',
                f => ({ email: f.querySelector('#signInEmail').value }),
                (r, div) => { div.innerHTML = '<p class="badge badge-success">Magic link sent!</p><p style="font-size: 0.75rem; color: #6b7280; margin-top: 0.5rem;">Check the server console for the link.</p>'; }
            );

            setupForm('inviteForm', '/invitations', 'POST',
                f => ({ email: f.querySelector('#inviteEmail').value }),
                (r, div) => { div.innerHTML = '<p class="badge badge-success">Invitation sent!</p>'; }
            );

            setupForm('grantForm', '/projects/alpha/grants', 'POST',
                f => ({ userId: f.querySelector('#grantUserId').value }),
                (r, div) => { div.innerHTML = '<p class="badge badge-success">Permission granted!</p>'; }
            );

            // Load users for the dropdown if admin
            if (document.getElementById('grantUserId')) {
                fetch('/admin/users')
                    .then(r => r.json())
                    .then(users => {
                        const select = document.getElementById('grantUserId');
                        select.innerHTML = '';
                        users.forEach(u => {
                            const opt = document.createElement('option');
                            opt.value = u.id;
                            opt.innerText = (u.name || 'No Name') + ' (' + u.email + ')';
                            select.appendChild(opt);
                        });
                    });
            }
        </script>
    """;

    public static IResult RenderDashboard(BootstrapStatus status, bool isAuthenticated, string? userEmail, bool isAdmin, bool canManageAlpha, bool canManageBeta)
    {
        var bootstrapSection = RenderBootstrapSection(status, isAuthenticated);
        var authSection = RenderAuthSection(status, isAuthenticated, userEmail);
        var adminSection = isAuthenticated && isAdmin ? AdminSection : "";
        var projectSection = isAuthenticated ? RenderProjectSection(canManageAlpha, canManageBeta) : "";

        var content = $$"""
            {{bootstrapSection}}
            {{authSection}}
            {{adminSection}}
            {{projectSection}}
            {{DashboardScripts}}
        """;

        return LandingPages.Layout("Dashboard", content);
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
                    <input type="email" id="bootstrapEmail" placeholder="admin@example.com" value="admin@example.com" required />
                    <input type="text" id="bootstrapUsername" placeholder="Admin Username" value="Admin" required />
                    <button type="submit">Bootstrap System</button>
                </form>
                <div id="bootstrapFormResult"></div>
            </div>
        """;
    }

    private static string RenderAuthSection(BootstrapStatus status, bool isAuthenticated, string? userEmail)
    {
        if (isAuthenticated)
        {
            return $"""
                <div class="card">
                    <h2>User Profile</h2>
                    <div style="margin-bottom: 1.5rem;">
                        <p style="margin: 0; font-weight: 600; font-size: 1.125rem;">{System.Net.WebUtility.HtmlEncode(userEmail ?? "")}</p>
                    </div>
                    <div class="grid">
                        <button class="secondary" onclick="location.href='/mfa/settings'">MFA Settings</button>
                        <form action="/auth/logout" method="POST"><button type="submit" class="secondary danger">Sign Out</button></form>
                    </div>
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
                <p>Enter your email to receive a magic link for signing in.</p>
                <form id="signInForm">
                    <input type="email" id="signInEmail" placeholder="your@email.com" required />
                    <button type="submit">Send Magic Link</button>
                </form>
                <div id="signInFormResult"></div>
            </div>
        """;
    }

    private static string RenderProjectSection(bool canManageAlpha, bool canManageBeta)
    {
        var alphaBadge = canManageAlpha ? "<span class=\"badge badge-success\">Manager</span>" : "<span class=\"badge\">No Access</span>";
        var betaBadge = canManageBeta ? "<span class=\"badge badge-success\">Manager</span>" : "<span class=\"badge\">No Access</span>";

        return $"""
            <div class="card">
                <h2>Projects</h2>
                <div class="status-box">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <span>Project: <strong>alpha</strong></span>
                        {alphaBadge}
                    </div>
                    <button class="secondary" onclick="location.href='/projects/alpha/manage'" { (canManageAlpha ? "" : "disabled") } style="margin-bottom: 1rem;">
                        Manage alpha
                    </button>

                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <span>Project: <strong>beta</strong></span>
                        {betaBadge}
                    </div>
                    <button class="secondary" onclick="location.href='/projects/beta/manage'" { (canManageBeta ? "" : "disabled") }>
                        Manage beta
                    </button>
                </div>
            </div>
        """;
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
                const sampleErrorMessages = {
                    handshake_not_found: 'Your sign-in session has expired. Request a new magic link and try again.',
                    invalid_mfa_code: 'That verification code was not accepted. Check the code and try again.',
                    invalid_totp: 'That authenticator code was not accepted. Check the code and try again.',
                    rate_limited: 'Too many attempts. Wait a moment, then try again.'
                };

                function formatSampleError(error, fallback) {
                    if (!error) return fallback;
                    if (sampleErrorMessages[error]) return sampleErrorMessages[error];
                    const message = String(error)
                        .replace(/_/g, ' ')
                        .replace(/\b\w/g, c => c.toUpperCase());
                    return /[.!?]$/.test(message) ? message : message + '.';
                }

                document.getElementById('signInButton').onclick = async (e) => {
                    const btn = e.target;
                    const resDiv = document.getElementById('result');
                    btn.disabled = true;
                    resDiv.innerText = 'Signing in...';

                    try {
                        const response = await fetch('/auth/magic-link/callback', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ t: '{{System.Web.HttpUtility.JavaScriptStringEncode(token)}}' })
                        });
                        const result = await response.json();
                        if (response.ok) {
                            if (result.status === 'mfa_required') {
                                document.querySelector('.card').innerHTML = '<h1>MFA Required</h1><p>Please enter your TOTP code or a recovery code below.</p><form id="mfaForm"><input type="text" id="mfaCode" placeholder="000000 or XXXX-XXXX-XXXX" required /><button type="submit">Verify MFA</button></form><div id="mfaResult"></div>';
                                document.getElementById('mfaForm').onsubmit = async (mfaE) => {
                                    mfaE.preventDefault();
                                    const mfaBtn = mfaE.target.querySelector('button');
                                    const mfaRes = document.getElementById('mfaResult');
                                    mfaBtn.disabled = true;
                                    try {
                                        const mfaResp = await fetch('/mfa/verify', {
                                            method: 'POST',
                                            headers: { 'Content-Type': 'application/json' },
                                            body: JSON.stringify({ handshakeToken: result.handshakeToken, code: document.getElementById('mfaCode').value })
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
                const sampleErrorMessages = {
                    invalid_invitation: 'This invitation is invalid or has expired. Ask an administrator to send a new invitation.',
                    rate_limited: 'Too many attempts. Wait a moment, then try again.'
                };

                function formatSampleError(error, fallback) {
                    if (!error) return fallback;
                    if (sampleErrorMessages[error]) return sampleErrorMessages[error];
                    const message = String(error)
                        .replace(/_/g, ' ')
                        .replace(/\b\w/g, c => c.toUpperCase());
                    return /[.!?]$/.test(message) ? message : message + '.';
                }

                document.getElementById('acceptForm').onsubmit = async (e) => {
                    e.preventDefault();
                    const btn = e.target.querySelector('button');
                    const resDiv = document.getElementById('result');
                    btn.disabled = true;
                    resDiv.innerText = 'Processing...';

                    try {
                        const response = await fetch('/invitations/accept', {
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

    public static IResult RenderMfaSetup(string sharedSecret, string authenticatorUri)
    {
        return LandingPages.Layout("MFA Setup", $$"""
            <div class="card">
                <h1>Setup MFA</h1>
                <p>Scan the QR code with your authenticator app to enable Two-Factor Authentication.</p>
                <div class="status-box" style="text-align: center;">
                    <div style="margin-bottom: 1rem; display: flex; justify-content: center;">
                        <canvas id="qr-code"></canvas>
                    </div>
                    <p>Shared Secret: <code>{{sharedSecret}}</code></p>
                </div>
                <form id="verifyForm">
                    <input type="hidden" id="secret" value="{{sharedSecret}}" />
                    <input type="text" id="code" placeholder="000000" required maxlength="6" />
                    <button type="submit">Verify & Enable MFA</button>
                </form>
                <div id="result"></div>
                <hr style="margin: 1.5rem 0; border: 0; border-top: 1px solid #e5e7eb;" />
                <button class="secondary" onclick="location.href='/'">Cancel</button>
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
                        const response = await fetch('/mfa/totp/verify', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ sharedSecret: document.getElementById('secret').value, code: document.getElementById('code').value })
                        });
                        if (response.ok) {
                            location.reload();
                        } else {
                            resDiv.style.color = '#dc2626';
                            resDiv.innerText = 'Invalid code. Please try again.';
                            btn.disabled = false;
                        }
                    } catch (err) { resDiv.innerText = 'Connection error.'; btn.disabled = false; }
                };
            </script>
        """);
    }

    public static IResult RenderMfaSettings(bool hasRecoveryCodes)
    {
        return LandingPages.Layout("MFA Settings", $$"""
            <div class="card">
                <h1>MFA Settings</h1>
                <div class="status-box">
                    <span class="badge badge-success">Enabled</span> Authenticator App (TOTP) is active.
                </div>

                <h2>Recovery Codes</h2>
                {{ (hasRecoveryCodes ? """<div class="status-box"><span class="badge badge-success">Generated</span> Recovery codes are configured for your account.</div>""" : """<div class="status-box"><span class="badge badge-warning">Action Required</span> You haven't generated recovery codes yet.</div>""") }}
                <p>Generate new recovery codes to access your account if you lose your MFA device. <strong>This will invalidate any previous codes.</strong></p>
                <button id="generateBtn">{{ (hasRecoveryCodes ? "Regenerate Recovery Codes" : "Generate Recovery Codes") }}</button>
                <div id="codesResult" style="margin-top: 1.5rem;"></div>

                <hr style="margin: 2rem 0; border: 0; border-top: 1px solid #e5e7eb;" />

                <h2>Reset MFA</h2>
                <p style="color: #6b7280; font-size: 0.875rem;">If you need to switch to a new authenticator app, you can reset your TOTP. This will invalidate your existing MFA setup.</p>
                <form id="resetForm">
                    <button type="submit" class="secondary danger">Reset Authenticator App</button>
                </form>
                <div id="resetResult"></div>

                <hr style="margin: 2rem 0; border: 0; border-top: 1px solid #e5e7eb;" />
                <button class="secondary" onclick="location.href='/'">Back to Dashboard</button>
            </div>
            <script>
                document.getElementById('generateBtn').onclick = async (e) => {
                    const btn = e.target;
                    const resDiv = document.getElementById('codesResult');
                    btn.disabled = true;
                    resDiv.innerText = 'Generating...';
                    try {
                        const response = await fetch('/mfa/recovery-codes', { method: 'POST' });
                        const result = await response.json();
                        if (response.ok) {
                            let html = '<p class="badge badge-warning">Write these down! They will not be shown again.</p><div class="grid" style="margin-top: 1rem;">';
                            result.codes.forEach(c => html += '<code>' + c + '</code>');
                            html += '</div>';
                            resDiv.innerHTML = html;
                        } else { resDiv.innerText = 'Error generating codes.'; btn.disabled = false; }
                    } catch (err) { resDiv.innerText = 'Connection error.'; btn.disabled = false; }
                };

                document.getElementById('resetForm').onsubmit = async (e) => {
                    e.preventDefault();
                    if (!confirm('Are you sure you want to reset your authenticator app? You will need to enroll again.')) return;
                    const btn = e.target.querySelector('button');
                    btn.disabled = true;
                    try {
                        const response = await fetch('/mfa/totp/reset', { method: 'POST' });
                        if (response.ok) {
                            location.reload();
                        } else {
                            alert('Reset failed.');
                            btn.disabled = false;
                        }
                    } catch (err) { alert('Connection error.'); btn.disabled = false; }
                };
            </script>
        """);
    }
}
