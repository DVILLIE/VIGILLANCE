# D'Vielle — Professional Project Documentation Master Index

Version 1.0 • 10 October 2026 • Complete authored documentation baseline for the current design stage

## Read this first

This suite contains fully written project-specific documents: requirements, engineering decisions, interfaces, procedures, risks, validation obligations and a detailed implementation sequence. It is not a collection of empty forms. Proposed implementation and operational commitments are marked as proposed; no approvals, test results or legal determinations have been fabricated.

The initial documentation request created documents without changing application source or deployment. The owner subsequently authorized implementation. [Current implementation progress and acceptance evidence](../implementation/IMPLEMENTATION_PROGRESS_AND_ACCEPTANCE_EVIDENCE_2026-10-10.md) now records source changes, actual validation and remaining work. Installation/services/Windows policy were not deployed during that source increment. This suite complements the existing repair, research and user-guide records.

## Document register

| Document | Register number |
|---|---:|
| [Project Charter and Product Strategy](01_Project_Charter_and_Product_Strategy.md) | 01 |
| [Product Requirements and User Journeys](02_Product_Requirements_and_User_Journeys.md) | 02 |
| [Software Requirements Specification](03_Software_Requirements_Specification.md) | 03 |
| [System Architecture and Trust Boundaries](04_System_Architecture_and_Trust_Boundaries.md) | 04 |
| [Data Model IPC and Integration Contracts](05_Data_Model_IPC_and_Integration_Contracts.md) | 05 |
| [Threat Model and Security Control Design](06_Threat_Model_and_Security_Control_Design.md) | 06 |
| [Privacy Data Governance and Impact Assessment](07_Privacy_Data_Governance_and_Impact_Assessment.md) | 07 |
| [AI Autonomy and Decision Engineering](08_AI_Autonomy_and_Decision_Engineering.md) | 08 |
| [Cryptography and Post Quantum Migration Plan](09_Cryptography_and_Post_Quantum_Migration_Plan.md) | 09 |
| [User Experience Accessibility and Brand Standards](10_User_Experience_Accessibility_and_Brand_Standards.md) | 10 |
| [Verification Validation and Acceptance Plan](11_Verification_Validation_and_Acceptance_Plan.md) | 11 |
| [Secure Development and Supply Chain Plan](12_Secure_Development_and_Supply_Chain_Plan.md) | 12 |
| [Installation Release Update and Migration Plan](13_Installation_Release_Update_and_Migration_Plan.md) | 13 |
| [Operations Support and Recovery Runbook](14_Operations_Support_and_Recovery_Runbook.md) | 14 |
| [Incident Response and Vulnerability Disclosure Plan](15_Incident_Response_and_Vulnerability_Disclosure_Plan.md) | 15 |
| [Risk Register and Resolution Management](16_Risk_Register_and_Resolution_Management.md) | 16 |
| [Step by Step Implementation Plan](17_Step_by_Step_Implementation_Plan.md) | 17 |
| [Requirements Traceability and Delivery Matrix](18_Requirements_Traceability_and_Delivery_Matrix.md) | 18 |
| [Research Evidence Register and Engineering Findings](19_Research_Evidence_Register_and_Engineering_Findings.md) | 19 |
| [Free Tooling Licensing and Distribution Assessment](20_Free_Tooling_Licensing_and_Distribution_Assessment.md) | 20 |
| [Project Governance Architecture Decisions and Change Control](21_Project_Governance_Architecture_Decisions_and_Change_Control.md) | 21 |
| [Engineering Resolution Dossier](22_Engineering_Resolution_Dossier.md) | 22 |
| [User Operating Guide and Safety Workflows](23_User_Operating_Guide_and_Safety_Workflows.md) | 23 |
| [Developer Onboarding and Engineering Handbook](24_Developer_Onboarding_and_Engineering_Handbook.md) | 24 |
| [Ethical Assessment Rules of Engagement](25_Ethical_Assessment_Rules_of_Engagement.md) | 25 |

## Reading routes

**Owner/product review:** Charter -> Product Requirements -> Software Requirements -> Engineering Resolution Dossier -> Step-by-Step Implementation Plan -> Risk Register.

**Engineering:** Architecture -> Data/IPC Contracts -> Threat Model -> Secure Development -> Implementation Plan -> Traceability -> Validation.

**Operations/release:** Installation and Release -> Operations Runbook -> Incident Response -> Free Tooling and Distribution -> User Guide.

**Intelligence and future protection:** AI Decision Engineering -> Cryptographic Migration -> Research Register -> Ethical Assessment Rules.

**Experience:** Product Journeys -> Brand/Accessibility -> User Guide -> Validation.

## Supporting project evidence

- [Security design framework](../SECURITY_DESIGN_FRAMEWORK_2026-10-10.md): mathematical planning and original acceptance cases.
- [Security advancement research](../SECURITY_ADVANCEMENT_RESEARCH_2026-10-10.md): earlier challenged questions and source register.
- [Installation/helper repair evidence](../REPAIR_INSTALL_PRIVILEGE_BOUNDARY.md): trusted staging and production helper remain deployment prerequisites.
- [Windows control repair evidence](../REPAIR_WINDOWS_CONTROLS.md): source/unit evidence boundaries.
- [Repair status](../REPAIR_STATUS_2026-10-09.md): source changes versus actual deployment.
- [Historical user guide](../USER_GUIDE.md): existing application context.

## Document control and precedence

The suite is version 1.0, Proposed for joint review. A human approval must be recorded explicitly before treating proposed automatic action scope or operational promises as accepted. User instructions and actual verified runtime facts take precedence over a stale document. Keep source/deployment evidence separate from aspirations.

Every future security-impacting change updates its requirements, threats, interfaces, acceptance case and operating behavior. Retain prior versions and record concrete revision changes. A missing runtime measurement is not repaired by rewriting it as a success.

## Implementation and research disposition

The implementation plan contains twenty ordered work packages with entry conditions, deliverables, exit tests and fallback behavior. It starts with source/deployment reconciliation and trusted mutation/recovery, then introduces intelligence and advanced assessment.

The research register covers the lifecycle and distinguishes opened sources, official indexed discovery, access failures and prior research. It records documentation contradictions and source-access resolutions. It does not assert entire-web completeness.

This documentation baseline is ready for review. Application execution, validated benchmarks, deployed service state and public legal/support policies are separate deliverables requiring their real evidence.

## Current protected-service implementation evidence

[Protected Authorization and Service Implementation](../implementation/PROTECTED_AUTHORIZATION_AND_SERVICE_IMPLEMENTATION_2026-10-10.md) records the scoped grant store, native client/host, administrative recovery, actual tests and remaining activation requirements.

[Evidence, Privacy, Resource Accounting and Recovery Continuation](../implementation/EVIDENCE_PRIVACY_RESOURCE_AND_RECOVERY_CONTINUATION_2026-10-10.md) records the new history controls, measured resources, evidence freshness, process-exit recovery and actual installed-service prerequisites.

[Protected Service Registration and Runtime Identity](../implementation/PROTECTED_SERVICE_REGISTRATION_AND_RUNTIME_IDENTITY_2026-10-10.md) records researched service-security decisions, exact runtime verification, private user binding, stopped registration, uninstall safeguards and actual acceptance results.

[Activation Attempt and Python 3.14 Migration Candidate](../implementation/ACTIVATION_ATTEMPT_AND_PYTHON314_MIGRATION_2026-10-10.md) records official runtime verification, the canceled Windows administrator launch, the prepared protected-stage candidate and unfulfilled activation prerequisites.

[Python 3.14 Protected Deployment and Launcher Repair](../implementation/PYTHON314_PROTECTED_DEPLOYMENT_2026-10-10.md) supersedes that historical cancellation checkpoint with actual installation, a running SYSTEM helper, live authentication, query-only access checks and scoped firewall recovery evidence.
# Latest continuation evidence

See [Product completion checkpoint](../implementation/PRODUCT_COMPLETION_CHECKPOINT_2026-10-10.md),
[actual protected increment deployment](../implementation/PROTECTED_INCREMENT_DEPLOYMENT_2026-10-10.md),
[negotiated TLS advancement](../implementation/TLS_KEY_EXCHANGE_ADVANCEMENT_2026-10-10.md)
and [third-party notice evidence](../legal/THIRD_PARTY_NOTICE_REVIEW_2026-10-10.md).
The older canceled approval and uninstalled-candidate sections are historical.
The whole-plan acceptance and public release gates remain explicitly recorded.


[Administrative actions and actual interrupted-upgrade recovery](../implementation/ADMINISTRATIVE_ACTIONS_AND_INTERRUPTION_RECOVERY_2026-10-10.md) records the latest installed controls, verified 5,792-file identity, actual exit-23 restoration and remaining acceptance gates.

[Same-day hybrid gate, parser repair and UDP acceptance progress](../implementation/SAME_DAY_HYBRID_GATE_AND_UDP_PROGRESS_2026-10-10.md) distinguishes the tested staged update from the unchanged installed runtime after declined Windows approvals.


- [Actual assessment review and staged consent correction](../implementation/ASSESSMENT_REVIEW_AND_CONSENT_CORRECTION_2026-10-10.md)
