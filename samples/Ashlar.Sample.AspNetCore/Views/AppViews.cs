using Ashlar.Identity.Models;

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
                    const response = await fetch(url, {
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

        function handleMfaRequired(handshakeToken) {
            document.querySelector('.card').innerHTML = '<h1>MFA Required</h1><p>Please enter your TOTP code or a recovery code below.</p><form id="mfaForm"><input type="text" id="mfaCode" placeholder="000000 or XXXX-XXXX-XXXX" required /><button type="submit">Verify MFA</button></form><div id="mfaResult"></div>';
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
            </div>
        """;
    }

    private static string RenderProjectSection(List<(string Id, string Name, bool HasAccess)> projects)
    {
        var projectItems = projects.Select(p => {
            var badge = p.HasAccess ? "<span class=\"badge badge-success\">Manager</span>" : "<span class=\"badge\">No Access</span>";
            var button = $"""<button class="secondary" onclick="location.href='/projects/{System.Web.HttpUtility.JavaScriptStringEncode(System.Net.WebUtility.UrlEncode(p.Id))}'" { (p.HasAccess ? "" : "disabled") } style="margin-top: 0.5rem; height: 2.5rem;">Manage {System.Net.WebUtility.HtmlEncode(p.Name)}</button>""";

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
                    { (projects.Count > 0 ? string.Join("", projectItems) : "No projects found.") }
                </div>
            </div>
        """;
    }

    public static IResult RenderAccountSettings(string userEmail, string? userName, bool isEmailVerified, bool hasTotp, bool hasRecoveryCodes, bool isAdmin)
    {
        var verifiedBadge = isEmailVerified
            ? "<span class=\"badge badge-success\">Verified</span>"
            : "<span class=\"badge badge-warning\">Unverified</span>";

        var verifyForm = isEmailVerified ? "" : """
            <hr style="margin: 2rem 0; border: 0; border-top: 1px solid #e5e7eb;" />
            <h3>Verify Email</h3>
            <p>Your email address is not yet verified.</p>
            <form id="verifyEmailForm">
                <button type="submit" class="secondary">Resend Verification Code</button>
            </form>
            <div id="verifyEmailFormResult"></div>
        """;

        var mfaStatus = hasTotp
            ? "<span class=\"badge badge-success\">Enabled</span> Authenticator App (TOTP) is active."
            : "<span class=\"badge badge-warning\">Disabled</span> Two-Factor Authentication is not configured.";

        var recoveryCodesButtonText = hasRecoveryCodes ? "Regenerate Recovery Codes" : "Generate Recovery Codes";
        var mfaActions = hasTotp
            ? $"""
                <div class="grid" style="margin-top: 1rem;">
                    <button id="generateBtn" class="secondary" style="height: 2.5rem;">{recoveryCodesButtonText}</button>
                    <button id="resetMfaBtn" class="secondary danger" style="height: 2.5rem;">Reset MFA</button>
                </div>
                <div id="codesResult" style="margin-top: 1.5rem;"></div>
              """
            : """
                <div style="margin-top: 1rem;">
                    <button onclick="location.href='/account/mfa/enroll'" style="height: 2.5rem;">Enable Authenticator App</button>
                </div>
              """;

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
                    <h3>Two-Factor Authentication</h3>
                    <div class="status-box" style="margin-top: 1rem;">
                        {{mfaStatus}}
                    </div>
                    {{mfaActions}}

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
                            const response = await fetch('/api/mfa/recovery-codes', { method: 'POST' });
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
                        const response = await fetch('/api/mfa/totp/reset', { method: 'POST' });
                        if (response.ok) { location.reload(); } else { alert('Reset failed.'); }
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
                        let info = '<div><strong>' + formatUA(s.userAgent) + '</strong><br/><small>' + sanitizedIp + ' &bull; Created: ' + new Date(s.createdAt).toLocaleString() + '</small></div>';
                        let action = '';
                        if (s.isCurrent) { action = '<span class="badge badge-success">Current Session</span>'; } else { otherSessionsCount++; action = '<button class="secondary danger" style="width: auto; height: auto; padding: 0.25rem 0.75rem; font-size: 0.75rem; margin: 0;" onclick="revokeSession(\'' + s.id + '\')">Revoke</button>'; }
                        item.innerHTML = info + action;
                        list.appendChild(item);
                    });
                    if (otherSessionsCount > 0) { revokeOthersBtn.classList.remove('hidden'); } else { revokeOthersBtn.classList.add('hidden'); }
                };

                window.revokeSession = async (id) => {
                    if (!confirm('Revoke this session?')) return;
                    const response = await fetch('/api/sessions/' + id, { method: 'DELETE' });
                    if (response.ok) loadSessions();
                };

                document.getElementById('revokeOthersBtn').onclick = async (e) => {
                    if (!confirm('Revoke all other sessions?')) return;
                    const response = await fetch('/api/sessions/others', { method: 'DELETE' });
                    if (response.ok) loadSessions();
                };

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

                fetch('/api/admin/users')
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
                                handleMfaRequired(result.handshakeToken);
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
