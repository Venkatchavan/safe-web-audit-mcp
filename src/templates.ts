/**
 * Public-good templates and emergency checklist.
 * All content is generic, defensive, and suitable for non-technical owners.
 */

export type TemplateName =
  | "security_txt"
  | "responsible_disclosure"
  | "password_policy"
  | "backup_checklist"
  | "incident_contact_plan";

export interface TemplateInput {
  name: TemplateName;
  contact_email?: string;
  org_name?: string;
  domain?: string;
}

export interface TemplateOutput {
  filename: string;
  mime: string;
  content: string;
  notes: string;
}

export function generateTemplate(input: TemplateInput): TemplateOutput {
  const org = input.org_name ?? "Your Organization";
  const email = input.contact_email ?? "security@example.com";
  const domain = input.domain ?? "example.com";

  switch (input.name) {
    case "security_txt": {
      const expiresIso = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString();
      const content = `# Place this file at  https://${domain}/.well-known/security.txt
Contact: mailto:${email}
Expires: ${expiresIso}
Preferred-Languages: en
Canonical: https://${domain}/.well-known/security.txt
Policy: https://${domain}/responsible-disclosure
`;
      return {
        filename: "security.txt",
        mime: "text/plain",
        content,
        notes:
          "Save this file at /.well-known/security.txt. Update Expires at least once per year.",
      };
    }
    case "responsible_disclosure": {
      const content = `# Responsible Disclosure Policy — ${org}

We welcome reports of security issues from researchers and the public.

## How to report

Email **${email}** with:
- A short description of the issue
- Steps to reproduce (if applicable)
- The URL or component affected
- Your name or handle (optional)

If the issue is sensitive, please request our PGP key in your first message.

## What we promise

- We will acknowledge your report within 5 business days.
- We will investigate in good faith and keep you informed.
- We will credit you (if you wish) once the issue is resolved.
- We will not pursue legal action against researchers acting in good faith and within this policy.

## Out of scope

- Denial-of-service attacks
- Social engineering of our staff
- Physical attacks
- Automated scans that produce noise without verification
- Issues already publicly disclosed

## Safe harbor

Activities conducted in a manner consistent with this policy will be considered authorized, and we will not initiate legal action against you.

Thank you for helping keep ${org} and our users safe.
`;
      return {
        filename: "responsible-disclosure.md",
        mime: "text/markdown",
        content,
        notes: "Publish this at /responsible-disclosure or link from your footer.",
      };
    }
    case "password_policy": {
      const content = `# Password Policy — ${org}

These rules apply to all staff, contractors, and volunteers with access to ${org} systems.

## Choosing a password

- Use a passphrase of at least **12 characters** (longer is better).
- Use a password manager. Don't reuse passwords across accounts.
- Do not write passwords on paper, sticky notes, or shared documents.

## Multi-factor authentication

- Enable MFA on **every** account that supports it (email, hosting, code, finance).
- Prefer authenticator apps or hardware keys; SMS only as a last resort.

## Sharing credentials

- Never share credentials over email, chat, or screenshots.
- Use the password manager's "share" feature, or rotate the password after a one-time hand-off.

## When something goes wrong

- If a password might have leaked, change it immediately and notify ${email}.
- If you lose a device with saved credentials, sign out remotely and rotate the most-sensitive passwords.

## Reviews

This policy is reviewed at least once a year.
`;
      return {
        filename: "password-policy.md",
        mime: "text/markdown",
        content,
        notes: "Adapt section names to your team. Have everyone read and acknowledge it.",
      };
    }
    case "backup_checklist": {
      const content = `# Backup Checklist — ${org}

## What to back up

- [ ] Website source code (in version control, off-host)
- [ ] Database dumps (daily for active sites, weekly otherwise)
- [ ] Uploaded media / user files
- [ ] DNS records and certificate config
- [ ] Critical email and document storage

## How

- [ ] At least one backup is **off-site** (different provider/region)
- [ ] At least one backup is **offline** or immutable (write-once)
- [ ] Backups are encrypted at rest
- [ ] Access to backups requires MFA

## Testing

- [ ] Restore drill performed at least once every 90 days
- [ ] Restore drill is documented (date, who, outcome)

## Rotation

- [ ] Daily backups kept for 14 days
- [ ] Weekly backups kept for 3 months
- [ ] Monthly backups kept for 1 year

## Contacts

- Backup owner: ${email}
- Hosting provider support: <fill in>
`;
      return {
        filename: "backup-checklist.md",
        mime: "text/markdown",
        content,
        notes: "Tick items as you implement them. The restore drill is the part most teams skip.",
      };
    }
    case "incident_contact_plan": {
      const content = `# Incident Contact Plan — ${org}

If you suspect a security incident (compromise, data leak, ransomware, account takeover), follow this plan.

## 1. Stop and breathe

Do **not** immediately wipe servers, delete logs, or "try fixes". Evidence matters.

## 2. Notify

Within 1 hour, contact:

- **Primary security contact:** ${email}
- **Backup contact:** <fill in second person>
- **Hosting provider support:** <fill in>
- **Legal / leadership:** <fill in>

## 3. Preserve

- Save webserver, application, and access logs to a separate location.
- Take a snapshot of affected systems if your provider supports it.
- Note times in UTC, and what you did.

## 4. Contain

- Rotate exposed credentials and API keys.
- Disable affected admin accounts; force password resets.
- Take exposed admin panels offline if needed.

## 5. Communicate

- If user data may be affected, plan a clear, factual notification to users
  (and regulators where required) within the legal timeframe.

## 6. Learn

- Within 14 days, write a short post-incident note: what happened, how we noticed, what we changed.

This plan lives at <internal URL>. Print a copy and keep it offline.
`;
      return {
        filename: "incident-contact-plan.md",
        mime: "text/markdown",
        content,
        notes: "Customize the contacts and provider details before you need this.",
      };
    }
  }
}

export function emergencyChecklist(opts: {
  scenario?: string;
  has_admin_panel?: boolean;
  handles_user_data?: boolean;
}): { title: string; steps: { step: string; detail: string }[]; reminders: string[] } {
  const steps: { step: string; detail: string }[] = [
    {
      step: "Stay calm and don't wipe anything yet.",
      detail:
        "The first instinct is to delete or rebuild. Wait — logs and snapshots are needed to understand what happened.",
    },
    {
      step: "Preserve logs and snapshots.",
      detail:
        "Copy webserver, application, and auth logs to a separate machine or storage bucket. If your hosting supports VM/disk snapshots, take one now.",
    },
    {
      step: "Rotate credentials and API keys.",
      detail:
        "Change passwords for hosting, DNS, email, code repos, payment providers, and any third-party integrations. Revoke and re-issue API keys.",
    },
    {
      step: "Force-logout users and reset session secrets.",
      detail:
        "Invalidate active sessions; rotate session-signing secrets so existing tokens stop working.",
    },
  ];
  if (opts.has_admin_panel) {
    steps.push({
      step: "Take exposed admin panels offline.",
      detail:
        "Restrict /admin, /wp-admin, etc. by IP or basic auth at the edge until you have rotated credentials and reviewed access logs.",
    });
  }
  steps.push(
    {
      step: "Contact your hosting provider.",
      detail:
        "Open a support ticket; they may see network indicators you cannot, and can help isolate the host.",
    },
    {
      step: "Check for backdoors and persistence.",
      detail:
        "Compare deployed files to a known-good source (git, backup). Look for new admin users, scheduled tasks, or unfamiliar SSH keys.",
    },
  );
  if (opts.handles_user_data) {
    steps.push({
      step: "Plan user notification.",
      detail:
        "If personal data may be affected, draft a short, factual notification. Check your jurisdiction's breach-notification deadline (e.g. 72 hours under GDPR).",
    });
  }
  steps.push({
    step: "Write a short post-incident note.",
    detail:
      "Within 14 days: what happened, how you noticed, what you changed. This is for the team — not a public post-mortem unless you choose.",
  });

  return {
    title: opts.scenario
      ? `Emergency response — ${opts.scenario}`
      : "Emergency response — suspected compromise",
    steps,
    reminders: [
      "This is a calm, defensive checklist — not a forensic procedure. If the incident is large or regulated, engage a professional incident-response firm.",
      "safe-web-audit will not perform any active investigation on your behalf.",
    ],
  };
}
