# Enterprise Cloud IAM Architecture & Engineering Reference: AWS vs. Google Cloud

This document provides a comprehensive technical reference for Identity and Access Management (IAM) across Amazon Web Services (AWS) and Google Cloud Platform (GCP). It covers internal mechanics, evaluation algorithms, token lifecycles, cross-cloud federation topologies, and enterprise governance patterns for Staff/Principal-level cloud security architects.

---

## 1. Tenancy Models & Resource Hierarchies

The structural boundaries of AWS and GCP govern policy propagation, administrative delegation, and the blast radius of security incidents.

```
AWS MULTI-ACCOUNT HIERARCHY                    GOOGLE CLOUD RESOURCE HIERARCHY
===========================                    ===============================
[ Organizations Root ]                         [ Organization (Cloud Identity) ]
         │                                                    │
  ┌──────┴──────┐                                      ┌──────┴──────┐
[ Core OU ] [ Workload OU ]                        [ Folder: Core ] [ Folder: Apps ]
     │             │                                       │               │
[ Account ]   [ Account ]                           [ Sub-Folder ]   [ Project: Prod ]
     │             │                                       │               │
(Local IAM Engine) (Local IAM Engine)               [ Project: Non-Prod ] (Cloud Storage,
(VPC, S3, Roles)   (VPC, EC2, KMS)                  (GCE, BigQuery)        Cloud Run)

```

### AWS: Account-Centric Boundary Model

* **The Account as the Hard Boundary:** In AWS, the AWS Account is the primary security, identity, and billing envelope. Every account maintains an independent, isolated IAM database and policy evaluation engine.
* **AWS Organizations:** Logical grouping mechanism organized into an Organization Root, nested Organizational Units (OUs, max depth of 5), and member accounts.
* **Control Planes:**
* **Service Control Policies (SCPs):** Centrally administered JSON policies attached to the Root, OUs, or Accounts. SCPs are guardrails that specify the *maximum available permissions* for affected accounts. They **never grant permissions**; they act as an authorization filter.
* **Resource Control Policies (RCPs):** Centrally administered boundary policies enforced on AWS resources (e.g., S3, KMS, SQS) across the organization to prevent external or non-compliant data access, enforcing strict resource perimeter constraints.


* **Trust & Inheritance:** Trust across accounts must always be explicitly declared. SCPs inherit downward through the OU tree using logical intersection (effective permissions are the intersection of all parent SCPs down to the account level). By default, an `Allow *` policy is attached at every level until explicitly modified.

### Google Cloud: Resource Manager & Lattice Inheritance

* **Single Unified Hierarchy:** Resources reside in a unified tree under a single **Organization** node (tied 1:1 to a Cloud Identity or Google Workspace directory domain), followed by **Folders** (nested up to 10 levels), and terminal nodes known as **Projects**.
* **Projects as Logical Containers:** A Project is not an identity boundary; it is an administrative grouping for billing, API enablement, and quota management. IAM is not siloed within a project.
* **Lattice Inheritance Model:** Policies are attached directly to any node in the hierarchy (Org, Folder, Project, or directly on supporting resources).
* Permissions inherit downward through union: $\text{Effective Allow} = \bigcup_{i=0}^{n} \text{Allow}_i$
* A permission granted at the Organization or Folder level **cannot be overridden or stripped** by standard Allow policies at a child Project level.
* Overrides require **IAM Deny Policies** or **Organization Policy Constraints**.



### Side-by-Side Structural Comparison

| Architectural Property | Amazon Web Services (AWS) | Google Cloud Platform (GCP) |
| --- | --- | --- |
| **Top-Level Root** | Organization Root (AWS Organizations) | Organization Node (Domain-anchored) |
| **Intermediate Containers** | Organizational Units (OUs, max depth: 5) | Folders (max depth: 10) |
| **Execution/Host Container** | AWS Account | Project |
| **Local IAM Database** | Yes (Each account evaluates its own identities) | No (Global, unified Resource Manager engine) |
| **Default Access Path** | Denied across accounts unless explicitly trusted | Inherited down the tree unless blocked by Deny/Org Policy |
| **Administrative Superuser** | Root User (per account; email/password + MFA) | Cloud Identity / Workspace Super Admin (Domain-wide) |

---

## 2. Identity Constructs & Principal Specifications

```
AWS PRINCIPAL TYPES                           GCP PRINCIPAL TYPES
===================                           ===================
├── IAM User (Long-term creds)                ├── Google Account (User email)
├── IAM Group (Principal collection)          ├── Google Group (Nested collaboration)
├── IAM Role (Dynamic STS assumption)         ├── Cloud Identity Dynamic Group
│    ├── EC2 Instance Profile                 ├── Service Account (Dual Identity/Resource)
│    ├── Lambda Execution Role                │    ├── User-managed
│    └── Cross-Account / Federated Role       │    ├── Google-managed (APIs)
└── Federated Web / SAML Identity             │    └── Service Agents (System-level)
                                              ├── Workload Identity Federation Principal
                                              └── Special Identifiers (allUsers, allAuthUsers)

```

### AWS Principal Primitives

* **IAM User:** A persistent credentialed identity within an individual account. Houses static credentials: console passwords and API access keys (`AKIA...`).
* **IAM Group:** A management construct to attach policies to multiple users simultaneously. **Architectural constraint:** An IAM Group *cannot* be listed as a `Principal` in a resource-based policy or trust policy.
* **IAM Role:** An identity with specific permissions that does not have long-term static credentials. It is assumed by a principal via the AWS Security Token Service (STS), which dispenses ephemeral credentials (`ASIA...`).
* **Instance Profile:** A container for an IAM role that passes credentials to an Amazon EC2 instance via the local Instance Metadata Service (IMDS).
* **Service-Linked Roles (SLRs):** Predefined roles linked directly to an AWS service. The service assumes the role to execute actions in your account on your behalf. These cannot be deleted while linked resources exist.



### Google Cloud Principal Primitives

* **Google Accounts & Cloud Identity Users:** Native identities mapped directly to real human users (`alice@example.com`), authenticated through Cloud Identity or federated third-party IdPs (Okta, Entra ID).
* **Google Groups:** Collections of Google accounts and service accounts (`group:cloud-platform-engineers@example.com`). Unlike AWS IAM Groups, a Google Group **can be directly targeted** in IAM policy bindings across any resource level.
* **Cloud Identity Dynamic Groups:** Groups whose membership is computed dynamically via identity attributes (e.g., `user.department == "Security"`).
* **Service Accounts (SA):** Machine identities identified by an email address (`sa-name@project-id.iam.gserviceaccount.com`).
* **Special Identifiers:**
* `allUsers`: Anyone on the public internet (unauthenticated).
* `allAuthenticatedUsers`: Any authenticated account worldwide (consumer Gmail, separate Cloud Identity domains, etc.), not restricted to your organization.



### The GCP Service Account Dual-Nature Mechanics

In Google Cloud, a Service Account functions as both a **Principal** and a **Resource**:

1. **Service Account as an Identity (Actor):** The SA is granted roles on projects, buckets, or datasets to perform actions.
2. **Service Account as a Resource (Target):** The SA exists as a managed resource within a project. Other identities require IAM permissions **on the service account resource itself** to manipulate it or assume its authority.
* `roles/iam.serviceAccountUser`: Allows a developer or compute resource to execute workloads as the SA.
* `roles/iam.serviceAccountTokenCreator`: Allows an identity to mint short-lived OAuth 2.0 access tokens, OIDC tokens, or sign payloads as the SA.



```
       [ Developer: user:alice@example.com ]
                         │
                         │ Has role: roles/iam.serviceAccountTokenCreator
                         │ ON Resource: projects/-/serviceAccounts/data-loader@...
                         ▼
        [ Service Account: data-loader@... ] (Acting as Identity)
                         │
                         │ Has role: roles/bigquery.admin
                         │ ON Resource: projects/analytics-prod
                         ▼
             [ BigQuery Datasets ]

```

---

## 3. Policy Specification, Grammars & Evaluation Engines

### AWS Policy Model & Policy Types

AWS IAM evaluates access across six distinct policy layers. The document format is strict JSON.

```
AWS IAM Policy Grammatical Structure:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "StatementIdentifier",
      "Effect": "Allow" | "Deny",
      "Principal": { "AWS": [ "arn:aws:iam::123456789012:root" ] }, // Used in Resource Policies
      "Action": [ "service:operation" ],
      "Resource": [ "arn:aws:service:region:account:resource" ],
      "Condition": {
        "Operator": { "ContextKey": "Value" }
      }
    }
  ]
}

```

#### The Six Policy Types in AWS

1. **Identity-Based Policies:** Attached to Users, Groups, or Roles. Can be Managed (AWS-managed or Customer-managed) or Inline.
2. **Resource-Based Policies:** Attached directly to resources (e.g., S3 Bucket Policies, KMS Key Policies, SQS Policies, IAM Role Trust Policies). These must explicitly designate the `Principal`.
3. **Permissions Boundaries:** An advanced feature where a customer-managed policy sets the maximum allowable permissions an identity-based policy can grant to an IAM entity (User or Role). Crucial for safe delegation of IAM creation rights to developers.
4. **Service Control Policies (SCPs):** Applied at OU/Account levels to filter out permissions.
5. **Resource Control Policies (RCPs):** Applied at OU/Account levels to restrict incoming resource operations.
6. **Session Policies:** Passed inline via the AWS STS API during programmatical role assumption (`AssumeRole`, `AssumeRoleWithWebIdentity`) to dynamically restrict the temporary session.

### AWS Evaluation Logic Flowchart

```
                            [ Request Arrives ]
                                     │
                                     ▼
                          [ Is there an Explicit Deny? ] ──── YES ────► [ DENY ]
                                     │ NO
                                     ▼
                          [ Is an SCP Blocking? ] ─────────── YES ────► [ DENY ]
                                     │ NO
                                     ▼
                     [ Is Call Within Same Account? ]
                               │             │
                             YES             NO (Cross-Account Call)
                               │             │
                               │             ▼
                               │   [ Allowed by Resource Policy? ] ── NO ──► [ DENY ]
                               │   AND [ Allowed by Identity Policy? ] ─ NO ──► [ DENY ]
                               │             │
                               │   ┌─────────┘ (Both must allow)
                               ▼   ▼
               [ Allowed by Identity OR Resource Policy? ] ─── NO ────► [ DENY ]
                               │ YES
                               ▼
               [ Exceeds Permissions Boundary? ] ───────────── YES ───► [ DENY ]
                               │ NO
                               ▼
               [ Exceeds Session Policy? ] ─────────────────── YES ───► [ DENY ]
                               │ NO
                               ▼
                            [ ALLOW ]

```

---

### GCP Policy Architecture: Bindings & Common Expression Language (CEL)

Google Cloud IAM is built on an atomic **Role-to-Member Binding** model, decoupling permissions from policies.

* **Permissions:** Expressed as granular verbs: `service.resource.action` (e.g., `compute.instances.start`, `storage.objects.get`).
* **Roles:** Collections of permissions.
* **Basic/Primitive Roles:** `Owner`, `Editor`, `Viewer` (Broad, historical, avoid in production).
* **Predefined Roles:** Managed by Google; updated dynamically when new APIs roll out.
* **Custom Roles:** User-curated sets of permissions. *Constraints:* Can only be defined at the Project or Organization level (not Folders). Cannot include permissions flagged as unsupported for custom roles.


* **Policy Object Structure:** A mapping of roles to members, optionally bounded by CEL conditions.

```json
{
  "bindings": [
    {
      "role": "roles/storage.objectAdmin",
      "members": [
        "group:infra-ops@example.com",
        "serviceAccount:app-backend@project-a.iam.gserviceaccount.com"
      ],
      "condition": {
        "title": "Enforce_Business_Hours_And_Location",
        "description": "Restrict deployment modifications to New York business hours",
        "expression": "request.time.getHours('America/New_York') >= 9 && request.time.getHours('America/New_York') <= 17 && resource.matchTag('1234567890/environment', 'production')"
      }
    }
  ],
  "version": 3
}

```

#### GCP IAM Deny Policies

Introduced to provide explicit hierarchical overrides:

* Enforced across the resource manager tree.
* Evaluated **prior** to any IAM Allow bindings.
* Can deny specific permissions (or groups of permissions) based on CEL conditions, terminating execution before standard Allow policies are parsed.

```
                    [ Incoming API Request Context ]
                                   │
                                   ▼
                    [ Does an IAM Deny Policy Apply? ] ──── YES ────► [ DENY ]
                                   │ NO
                                   ▼
                    [ Traverse Hierarchy Upwards: ]
                    [ Resource -> Project -> Folder -> Org ]
                                   │
                                   ▼
                    [ Does an Allow Binding Match? ] ─────── NO ────► [ DENY ]
                                   │ YES
                                   ▼
                    [ Does a CEL Condition Fail? ] ───────── YES ───► [ DENY ]
                                   │ NO
                                   ▼
                               [ ALLOW ]

```

---

## 4. Federated Identity & Cross-Platform Machine Authentication

Modern enterprise zero-trust architectures mandate keyless authentication. Both platforms provide native Workload Identity Federation to eliminate static, long-lived API keys and service account JSON keys.

### AWS STS & Federated Mechanisms

AWS Security Token Service (STS) is the central token broker.

* **`AssumeRole`:** Used within AWS accounts or cross-account to assume an IAM Role.
* **`AssumeRoleWithWebIdentity`:** Native protocol for OIDC federation. Consumes an external JWT (e.g., GitHub Actions, Kubernetes Service Account) without needing AWS IAM Users.
* **`AssumeRoleWithSAML`:** Consumes SAML 2.0 assertions from enterprise IdPs (e.g., PingFederate, Active Directory Federation Services).
* **AWS IAM Roles Anywhere:** Extends IAM roles to on-premises servers, containers, and hardware by using an enterprise Public Key Infrastructure (PKI) Certificate Authority (CA) and X.509 certificates to establish cryptographic trust with STS.

#### Mechanics of AWS STS Token Issuance

```
[ Workload ] ────────────── 1. Sends Signed JWT ─────────────► [ AWS STS Endpoint ]
     │                                                               │
     │                                                               ├─► Validates OIDC JWKS
     │                                                               └─► Evaluates Role Trust Policy
     ▼                                                                         │
[ Recovers AWS Credentials ] ◄── 2. Returns Temp Credentials ──────────────────┘
  - AWS_ACCESS_KEY_ID (Starts with "ASIA...")
  - AWS_SECRET_ACCESS_KEY
  - AWS_SESSION_TOKEN

```

Every subsequent AWS REST call signs the request using the **AWS Signature Version 4 (SigV4)** algorithm, which computes a keyed HMAC (SHA-256) over the canonicalized HTTP request string, incorporating the session token in the `x-amz-security-token` header.

---

### GCP Workload Identity Federation (WIF)

GCP enables external identities (AWS IAM, Azure AD, GitHub, HashiCorp Vault, Kubernetes) to impersonate a Google Cloud Service Account directly.

```
                    WORKLOAD IDENTITY FEDERATION ARCHITECTURE
                    ========================================
[ External Workload ] ── 1. Exchange External Token (AWS STS/OIDC) ──► [ GCP STS Engine ]
                                                                             │
                                                                             ▼
                                                                [ Workload Identity Pool ]
                                                                - Token validation
                                                                - Attribute mapping & conditions
                                                                             │
                                                                             ▼
[ Returns Short-Lived GCP Access Token ] ◄─ 3. Mint OAuth Token ─ [ IAM Credentials API ]
                                                                             │
                                                                             ▼
                                                                [ Target Service Account ]
                                                                (Impersonated via
                                                                roles/iam.workloadIdentityUser)

```

1. **Workload Identity Pool:** An administrative entity hosting identity provider connections.
2. **Workload Identity Provider:** Contains the OIDC issuer URL, JWKS configuration, or AWS Account IDs.
3. **Attribute Mapping:** Extracts claims from the incoming token and maps them to Google token attributes:
* `google.subject = assertion.sub`
* `attribute.repository = assertion.repository`
* `attribute.aws_role = assertion.arn`


4. **Attribute Condition:** CEL check ensuring only explicit workloads authenticate:
`attribute.repository == "enterprise/production-backend" && attribute.ref == "refs/heads/main"`
5. **Security Token Service Exchange:** Exchanging the external token generates a short-lived Federated Token, which is then submitted to the Cloud IAM Credentials API to impersonate the target service account.

---

## 5. Architectural Deep-Dive: Kubernetes Identity Integration

Comparing Amazon Elastic Kubernetes Service (EKS) and Google Kubernetes Engine (GKE).

```
EKS: POD IDENTITY / IRSA                       GKE: WORKLOAD IDENTITY
========================                       ======================
[ Pod: ServiceAccount ]                        [ Pod: ServiceAccount ]
       │                                              │
       ├─► (IRSA): Assumes IAM Role via OIDC          ├─► Intercepts link-local metadata call
       │   JWT injected via webhook                   │   (169.254.169.254) via GKE daemon
       │                                              │
       └─► (Pod Identity): Mutating webhook           └─► Cloud IAM exchanges KSA token
           passes auth directly via daemon agent          for Google OAuth Access Token

```

### AWS EKS: IRSA vs. EKS Pod Identity

#### 1. IAM Roles for Service Accounts (IRSA)

* An OIDC Discovery Endpoint is provisioned per EKS cluster.
* A mutating admission webhook injects two environment variables into the pod: `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`, along with a projected volume containing a short-lived OIDC token.
* The AWS SDK reads this token and calls `sts:AssumeRoleWithWebIdentity`.
* **Scalability Bottleneck:** Highly scaled clusters can trigger AWS STS rate limits. Trust policies must explicitly maintain the cluster OIDC URL, which causes friction during cluster migrations.

#### 2. EKS Pod Identity (Modern Architecture)

* Avoids the external OIDC federation path entirely.
* An EKS daemon agent runs on each node and intercepts calls directed at the local metadata service.
* A cluster-level association links the Kubernetes Service Account directly to the IAM Role via an AWS API call (`aws eks create-pod-identity-association`).
* The agent assumes the role directly on behalf of the pod using cluster control plane credentials, preventing STS rate limiting and eliminating complicated trust policy updates.

### Google Cloud: GKE Workload Identity

* Replaces the native metadata server endpoint on the worker nodes with the **GKE Metadata Server** (a local proxy daemon).
* The Kubernetes Service Account (KSA) is annotated with the Google Service Account (GSA):
`iam.gke.io/gcp-service-account: gsa-name@project-id.iam.gserviceaccount.com`
* The GSA trust policy contains a binding to the KSA identifier:
`principal://[iam.googleapis.com/projects/](https://iam.googleapis.com/projects/){project_number}/locations/global/workloadIdentityPools/{project_id}.svc.id.goog/subject/ns/{namespace}/sa/{ksa-name}`
* When an application inside the pod calls `[http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token](http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token)`, the GKE metadata server intercepts the call, validates the pod's identity via the Kubernetes token review API, and returns an ephemeral Google OAuth 2.0 access token for the GSA.

---

## 6. Access Governance, Auditing & Automated Reasoning

| Architecture Area | AWS Ecosystem | Google Cloud Ecosystem |
| --- | --- | --- |
| **Policy Analysis & Verification** | **IAM Access Analyzer:** Uses Automated Reasoning (SMT Solvers) to mathematically prove policy outcomes. | **Policy Analyzer & Policy Simulator:** Deterministic graph walk over current IAM policies and Asset Inventory. |
| **Audit Logs** | **AWS CloudTrail:** Captures all management events (`AssumeRole`, `CreateUser`) and data events (`S3 GetObject`). | **Cloud Audit Logs:** Admin Activity logs (immutable, free), Data Access logs (disabled by default due to volume). |
| **Least Privilege Mining** | IAM Access Analyzer policy generation based on CloudTrail log mining. | **IAM Recommender:** Machine learning-based access recommender analyzing 90-day activity histories. |
| **Perimeter Boundary** | **VPC Endpoints & Resource Policies:** Restricts requests to specific networks via `aws:sourceVpce` and `aws:sourceVpc`. | **VPC Service Controls (VPC-SC):** Ingress/Egress rules enforcing cryptographic data-perimeters around APIs. |

### AWS IAM Access Analyzer: Provable Security Engine

AWS IAM Access Analyzer does not rely solely on heuristics or log parsing. It uses **Formal Logic and Automated Reasoning (SMT Solvers)** to analyze policies:

* Converts IAM policy JSON documents into formal first-order logic equations.
* Evaluates all possible combinations of variables to determine whether an external, unauthorized principal could ever evaluate to `Allow`.
* Emits proactive alerts when S3 buckets, KMS keys, or IAM roles are configured with policies allowing public or cross-account exposure before traffic is even received.

### Google Cloud: VPC Service Controls (VPC-SC)

IAM controls **Identity Authentication & Authorization**, but does not control network perimeter dynamics. GCP uses VPC-SC to bridge this gap:

* Creates a secure boundary around Google-managed service APIs (Cloud Storage, BigQuery, Vertex AI).
* Even if an identity possesses valid `roles/storage.admin` credentials, if the API call originates from outside the designated Service Perimeter (defined by IP, VPC network, or device posture), the request is rejected at the API proxy layer with an HTTP 403.
* Prevents data exfiltration by blocking internal identities inside the perimeter from copying project data to unauthorized external cloud storage buckets.

---

## 7. Comparative Technical Matrix

| Capability | AWS IAM | GCP Cloud IAM | Staff-Level Architectural Tradeoff |
| --- | --- | --- | --- |
| **Attribute-Based Access Control (ABAC)** | Supported natively via resource tags, principal tags, and request tags (`aws:PrincipalTag/Dept`). | Implemented using Resource Manager Tags and CEL expressions (`resource.matchTag()`). | AWS ABAC is more pervasive across diverse cloud services; GCP CEL is more expressive for complex conditional logic. |
| **Group Policies** | Groups cannot be referenced as a `Principal` in policies; permissions are indirectly applied. | Groups can be assigned direct roles on any resource in the hierarchy. | GCP allows dynamic directory group federation without requiring per-account identity mapping. |
| **Policy Synthesis** | Policies are individual documents; multiple overlapping policies apply per role/user. | Policies are centrally held by the resource containing binding arrays. | AWS identity documents provide fine-grained control; GCP centralized bindings simplify resource-level audits. |
| **Credential Rotation** | Native IAM User access key rotation requires custom automation or Secrets Manager. | Cloud IAM does not require user access keys; short-lived tokens are native. Service account keys can be disabled globally via Org Policy. | GCP's native architecture minimizes reliance on static API keys. |
| **Token Mechanics** | AWS STS issues Session Tokens; REST calls require local SigV4 HMAC computation. | IAM Credentials API issues standard Bearer OAuth 2.0 Access Tokens (opaque/JWT). | Google's bearer tokens are simpler for direct HTTP calls; AWS SigV4 prevents token replay attacks if raw headers are leaked. |

---

## 8. Principal-Level Interview Scenarios & Whiteboard Solutions

### Scenario A: Mitigating Metadata Service Credential Exfiltration (SSRF Defense)

* **Problem:** An application running on an instance/VM has an SSRF (Server-Side Request Forgery) vulnerability. An attacker attempts to read the local metadata endpoint to capture temporary credentials.
* **AWS Whiteboard Defense:**
1. Enforce **IMDSv2** globally across the account via an SCP: `ec2:MetadataHttpTokens = required`.
2. Set the HTTP response hop limit to `1` (`ec2:MetadataHttpPutResponseHopLimit = 1`). This blocks containerized workloads or reverse proxies from fetching the initial `PUT` token, as the TTL expires before reaching downstream networks.
3. Attach an IAM Permission Boundary to the instance role requiring `aws:ViaAWSService = false` or enforcing network condition limits via `aws:SourceIp` / `aws:sourceVpc`.


* **GCP Whiteboard Defense:**
1. Enforce the Organization Policy Constraint: `constraints/compute.disableGuestAttributes` and disable legacy metadata endpoints.
2. Block access to `metadata.google.internal` from container workloads by running **GKE Workload Identity**, which replaces the default link-local server with a secure proxy.
3. Ensure no static service account keys exist by setting the Org Policy: `constraints/iam.disableServiceAccountKeyCreation`.



### Scenario B: Multi-Tenant Data Lake Access Control

* **Problem:** A core data lake account/project must expose analytical data to external business units without exposing underlying encryption keys or granting persistent access.
* **AWS Strategy:**
1. Define S3 Bucket with cross-account access in its Bucket Policy targeting the external Role ARN.
2. Target data encrypted using an AWS KMS Customer Managed Key (CMK).
3. **Crucial AWS Architectural Rule:** Cross-account S3 access fails if the KMS Key Policy does not explicitly grant the external Account ID permission to `kms:Decrypt`. Bucket policy authorization alone is insufficient.
4. The external Account Administrator must then delegate `kms:Decrypt` and `s3:GetObject` to the consumer's IAM Role.


* **GCP Strategy:**
1. Grant `roles/storage.objectViewer` directly on the specific Cloud Storage bucket to the external Identity (e.g., `group:analytics@partner.com` or `serviceAccount:consumer@project-b.iam.gserviceaccount.com`).
2. If using Customer-Managed Encryption Keys (CMEK), grant `roles/cloudkms.cryptoKeyEncrypterDecrypter` directly to the **Storage Service Agent** of the data lake project, not the consumer identity. GCP abstracts the KMS consumer access via the service agent, simplifying permission delegation.
3. Enforce **VPC Service Controls** with an Ingress Rule allowing cross-project calls only from the partner's designated network perimeter.
