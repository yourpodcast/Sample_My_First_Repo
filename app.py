# IS Impact & Domain Classifier
# -------------------------------

# 1. Define the IS domain prompts
domain_prompts = {
    "Identification/Authentication/Authorization/Access Control/Entitlement": """
- New user creation or changes to existing users.
- New bot user creation or changes to existing bot users.
- Application role changes (new application roles, changes to entitlements).
- New setup/incremental changes to shared authentication platforms (AD, SSO, LDAP, KDC).
- Directory services setup or mapping.
- Custom authentication for middleware components.
- Multi-factor authentication (MFA) setup or modification.
- Hardware/software token mechanism changes.
- PIN-based or knowledge-based authentication changes.
- System-to-system authentication setup.
""",
    "Data Security/Cryptography": """
- Cryptographic key generation, renewal, deletion, or modifications.
- Changes to cryptographic libraries.
- SSL certificate creation or changes.
- Digital signatures or hash function updates.
- Database/transit encryption setup or changes.
- Data masking or obfuscation requirements.
- Hardware Security Module (HSM) setup or changes.
- Password-based encryption updates.
- Data migration from production to non-prod.
- Change in information classification.
- Key distribution updates.
""",
    "Application Security": """
- New or changed application (web, desktop, mobile).
- Application/server/middleware deployment or updates.
- Configuration or technology changes in servers.
- Migration to cloud platforms (SaaS, PaaS, IaaS).
- Software patch deployments.
- Application re-architecting.
- Logging mechanism changes.
- Session management updates.
- SMS or file upload setup changes.
- Regulatory compliance (PCI, SOX, HIPAA).
- AI/ML or blockchain integration.
- New or changed application/API interfaces.
- Gateway (API/payment) setup or changes.
- Application decommissioning.
""",
    "Administrative Security / Network & Perimeter Security / Vulnerability Assessment": """
Administrative Security:
- Functional ID setup or modification.
- Maker/checker functionality changes.
- Delegation or entitlement admin actions.
- EERS feed setup or updates.

Network & Perimeter Security:
- VPN implementation or changes.
- Deployment in demilitarized zone (DMZ).
- Application architecture changes.

Vulnerability Assessment:
- Internet-facing app/component updates.
- ATM/IVR app changes.
- SOX/OCC WP application changes.
"""
}

# 2. Build the prompt using full story context
def format_prompt(story: dict) -> str:
    full_story = f"""
Story Summary:
{story.get("summary", "")}

Description:
{story.get("description", "")}

Acceptance Criteria:
{story.get("acceptance_criteria", "")}
"""

    prompt = f"""
You are a senior security analyst.

Your task is to analyze the following Jira story and determine:
1. Is there any *Information Security (IS) Impact*? Answer 'Yes' or 'No'.
2. If Yes, classify it into one of the following six IS domains.

Consider all parts of the Jira story: summary, description, and acceptance criteria.

---

Domain 1 - Identification/Authentication/Authorization/Access Control/Entitlement:
{domain_prompts["Identification/Authentication/Authorization/Access Control/Entitlement"]}

Domain 2 - Data Security/Cryptography:
{domain_prompts["Data Security/Cryptography"]}

Domain 3 - Application Security:
{domain_prompts["Application Security"]}

Domains 4, 5 & 6 - Administrative Security / Network & Perimeter Security / Vulnerability Assessment:
{domain_prompts["Administrative Security / Network & Perimeter Security / Vulnerability Assessment"]}

---

Jira Story for Review:
{full_story}

---

Output Format (strict):
IS Impact: <Yes/No>
Domain: <Domain Name> (Only if IS Impact is Yes)
"""
    return prompt

# 3. Analyze stories using LLM
def analyze_stories_with_llm(stories, get_llm_response):
    results = []

    for story in stories:
        prompt = format_prompt(story)
        response = get_llm_response(prompt)

        is_impact = "Yes" if "IS Impact: Yes" in response else "No"
        domain_line = next((line for line in response.splitlines() if line.lower().startswith("domain:")), None)
        domain = domain_line.split(":", 1)[1].strip() if domain_line and is_impact == "Yes" else "None"

        results.append({
            "issue_key": story.get("issue_key", ""),
            "summary": story.get("summary", ""),
            "IS Impact": is_impact,
            "IS Domain": domain,
            "LLM Response": response
        })

    return results
  

def process_stories(df):
    """Main processing function with IS Impact and domain tagging."""
    stories = []
    for _, row in df.iterrows():
        story = {
            "issue_key": row.get("Key", ""),
            "summary": row.get("Summary", ""),
            "description": row.get("Description", ""),
            "acceptance_criteria": row.get("Acceptance Criteria", ""),
        }

        decision, reasons = evaluate_story_quality(
            story["description"], story["summary"], story["acceptance_criteria"]
        )
        story["Flag"] = decision
        story["Reason"] = "\n".join(reasons)

        # IS Impact & Security Domain
        is_impact, security_domain = determine_is_impact_and_domain(
            story["summary"], story["description"], story["acceptance_criteria"]
        )
        story["IS Impact"] = is_impact
        story["Security Domain"] = security_domain

        # Domain and Risk (if IS Impact exists)
        if is_impact == "Yes":
            domain, justification = classify_domain(story["Reason"])
            risk = analyze_risk(story["Reason"])

            story["Domain"] = domain
            story["Domain Justification"] = justification
            story.update(risk)
        else:
            story["Domain"] = "N/A"
            story["Domain Justification"] = "No IS impact detected"
            story["Risk Rating"] = 0
            story["Change Type"] = "N/A"
            story["Security Risk"] = "No"
            story["Recommendation"] = "Auto-Approve"
            story["Justification"] = "No security relevance"

        stories.append(story)
    return stories
