#pragma once
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <algorithm>
#include "remediation_engine.h"

namespace LicenseInspector {

constexpr int DEFAULT_EVENT_LIMIT = 200;

// ─── Severity ────────────────────────────────────────────────────────────────
enum class Severity {
    INFO = 0,
    CLEAN = 1,
    WARNING = 2,
    TAMPERING = 3
};

// ─── FindingType ─────────────────────────────────────────────────────────────
enum class FindingType {
    LICENSE_STATE     = 0, // Trạng thái bản quyền (Licensed, Grace, Notification)
    FORENSIC_EVIDENCE = 1, // Dấu vết can thiệp (Rogue KMS, PowerShell crack, MAS, KMS38)
    CONFIGURATION     = 2, // Cấu hình hệ thống (TPM, Secure Boot, policies)
    INFORMATION       = 3  // Chỉ để hiển thị thông tin
};

// ─── SIEM / DFIR Domains & Origins ───────────────────────────────────────────
enum class EvidenceDomain {
    WINDOWS       = 1,
    OFFICE        = 2,
    ADOBE         = 3,
    VISUAL_STUDIO = 4,
    SQL_SERVER    = 5
};

enum class EdgeStrength {
    WEAK   = 1,
    MEDIUM = 2,
    STRONG = 3
};

enum class EvidenceOrigin {
    OBSERVED   = 0,
    DERIVED    = 1,
    CORRELATED = 2
};

// ─── Type-Safe Bitwise EvidenceCategory ──────────────────────────────────────
enum class EvidenceCategory : uint32_t {
    NONE       = 0,
    HARDWARE   = 1 << 0,
    FIRMWARE   = 1 << 1,
    REGISTRY   = 1 << 2,
    SERVICE    = 1 << 3,
    NETWORK    = 1 << 4,
    FILESYSTEM = 1 << 5,
    WMI        = 1 << 6,
    COM        = 1 << 7,
    EVENTLOG   = 1 << 8
};

inline constexpr EvidenceCategory operator|(EvidenceCategory a, EvidenceCategory b) {
    return static_cast<EvidenceCategory>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline constexpr EvidenceCategory operator&(EvidenceCategory a, EvidenceCategory b) {
    return static_cast<EvidenceCategory>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}
inline constexpr EvidenceCategory operator^(EvidenceCategory a, EvidenceCategory b) {
    return static_cast<EvidenceCategory>(static_cast<uint32_t>(a) ^ static_cast<uint32_t>(b));
}
inline constexpr EvidenceCategory operator~(EvidenceCategory a) {
    return static_cast<EvidenceCategory>(~static_cast<uint32_t>(a));
}
inline constexpr EvidenceCategory& operator|=(EvidenceCategory& a, EvidenceCategory b) {
    return a = a | b;
}
inline constexpr EvidenceCategory& operator&=(EvidenceCategory& a, EvidenceCategory b) {
    return a = a & b;
}
inline constexpr bool hasFlag(EvidenceCategory mask, EvidenceCategory flag) {
    return (static_cast<uint32_t>(mask) & static_cast<uint32_t>(flag)) != 0;
}

// ─── FindingRole & FindingDisposition ────────────────────────────────────────
enum class FindingRole {
    PRIMARY       = 0, // Direct forensic evidence (VD: A1, A3, A9, A13)
    SUPPORTING    = 1, // Cross-validation indicator (VD: A14, A10, A2, A11)
    CORROBORATIVE = 2  // Corroborative evidence across domains
};

enum class FindingDisposition {
    NORMAL             = 0,
    LEGITIMATE_UPGRADE = 1,
    SUSPICIOUS         = 2,
    TAMPERED           = 3
};

enum class ActivationMechanism {
    UNKNOWN,
    OEM_HARDWARE,
    RETAIL_KEY,
    GVLK_INSTALLED,
    KMS_ACTIVATED,
    MAK_KEY,
    DIGITAL_ENTITLEMENT,
    KMS38_EVAL,
    TOKEN_BASED,
    AVMA
};

enum class LicenseProgram {
    UNKNOWN,
    RETAIL_PERPETUAL,
    OEM_PERPETUAL,
    VOLUME_LICENSE,
    M365_SUBSCRIPTION,
    ENTRA_ID_AAD,
    ACADEMIC_EES
};

enum class LicenseEdition {
    UNKNOWN,
    CORE_HOME,
    CORE_HOME_SL,
    PROFESSIONAL,
    ENTERPRISE,
    EDUCATION,
    SERVER,
    IOT,
    LTSC
};

enum class LicenseChannel {
    UNKNOWN,
    OEM_DM,
    OEM_NONSLP,
    OEM_COA,
    RETAIL,
    VOLUME_GVLK,
    VOLUME_MAK,
    DIGITAL_ENTITLEMENT
};

enum class EditionFamily {
    UNKNOWN,
    HOME,
    PROFESSIONAL,
    ENTERPRISE,
    EDUCATION,
    SERVER,
    IOT
};

inline EditionFamily getEditionFamily(LicenseEdition ed) {
    switch (ed) {
        case LicenseEdition::CORE_HOME:
        case LicenseEdition::CORE_HOME_SL:
            return EditionFamily::HOME;
        case LicenseEdition::PROFESSIONAL:
            return EditionFamily::PROFESSIONAL;
        case LicenseEdition::ENTERPRISE:
        case LicenseEdition::LTSC:
            return EditionFamily::ENTERPRISE;
        case LicenseEdition::EDUCATION:
            return EditionFamily::EDUCATION;
        case LicenseEdition::SERVER:
            return EditionFamily::SERVER;
        case LicenseEdition::IOT:
            return EditionFamily::IOT;
        default:
            return EditionFamily::UNKNOWN;
    }
}

inline const wchar_t* editionFamilyToString(EditionFamily fam) {
    switch (fam) {
        case EditionFamily::HOME:         return L"Windows Home Family";
        case EditionFamily::PROFESSIONAL: return L"Windows Professional Family";
        case EditionFamily::ENTERPRISE:   return L"Windows Enterprise Family";
        case EditionFamily::EDUCATION:    return L"Windows Education Family";
        case EditionFamily::SERVER:       return L"Windows Server Family";
        case EditionFamily::IOT:          return L"Windows IoT Family";
        default:                          return L"Unknown Edition Family";
    }
}

struct FirmwareLicenseInfo {
    bool                firmwarePresent     = false;
    bool                virtualMachine      = false;
    bool                digitalEntitlement  = false;

    std::wstring        firmwareKeyHash;    // SHA-256 BCrypt hex string
    std::wstring        firmwarePartialKey; // XXXXX-XXXXX-...-LAST5
    std::wstring        firmwareDescRaw;
    LicenseEdition      firmwareEdition     = LicenseEdition::UNKNOWN;
    LicenseChannel      firmwareChannel     = LicenseChannel::UNKNOWN;

    std::wstring        currentNameRaw;
    std::wstring        currentDescRaw;
    LicenseEdition      currentEdition      = LicenseEdition::UNKNOWN;
    LicenseChannel      currentChannel      = LicenseChannel::UNKNOWN;
    ActivationMechanism currentMechanism    = ActivationMechanism::UNKNOWN;
    LicenseProgram      currentProgram      = LicenseProgram::UNKNOWN;

    std::wstring        kmsMachine;
    int                 licenseStatus       = 0;
};

enum class EvidenceImpact {
    INFO_ONLY = 0,
    LOW     = 1,
    MEDIUM  = 2,
    HIGH    = 3
};

enum class EvidenceQuality {
    INFO_ONLY = 0,
    LOW       = 1,
    MEDIUM    = 2,
    HIGH      = 3
};

enum class EvidenceReliability {
    WEAK     = 0,
    MODERATE = 1,
    STRONG   = 2,
    VERIFIED = 3
};

enum class VerificationStatus {
    FOUND          = 0,
    NOT_FOUND      = 1,
    ERROR_OCCURRED = 2,
    ACCESS_DENIED  = 3,
    UNSUPPORTED    = 4,
    NOT_APPLICABLE = 5
};

enum class FindingState {
    UNKNOWN        = 0,
    NOT_APPLICABLE = 1,
    DETECTED       = 2,
    SUSPECTED      = 3,
    VERIFIED       = 4
};

enum class ForensicSource {
    NONE                   = 0,
    NETWORK_SERVER         = 1,
    STATIC_ARTIFACT        = 2,
    SCHEDULING_EXECUTION   = 3,
    REGISTRY_COM_TAMPERING = 4,
    CORE_LICENSING_HOOK    = 5,
    LICENSE_STATE          = 6
};

enum class ConfidenceLevel {
    NONE      = 0,
    LOW       = 1,
    MEDIUM    = 2,
    HIGH      = 3,
    VERY_HIGH = 4
};

enum class EdgeRelation {
    USES,
    SUPPORTS,
    CONTRADICTS,
    TRIGGERS,
    CORROBORATES
};

enum class GraphConfidence {
    NORMAL,
    CONFIRMED
};

template <typename T>
struct CollectorResult {
    T                   data;
    EvidenceReliability reliability        = EvidenceReliability::WEAK;
    VerificationStatus  verificationStatus = VerificationStatus::NOT_FOUND;
    std::wstring        collectorName;
    std::wstring        timestamp;
    double              durationMs         = 0.0;
    std::wstring        errorDetail;

    static CollectorResult<T> success(T val, EvidenceReliability rel, const std::wstring& name, double ms = 0.0) {
        return { std::move(val), rel, VerificationStatus::FOUND, name, L"", ms, L"" };
    }
    static CollectorResult<T> notFound(EvidenceReliability rel, const std::wstring& name, double ms = 0.0) {
        return { T{}, rel, VerificationStatus::NOT_FOUND, name, L"", ms, L"" };
    }
    static CollectorResult<T> accessDenied(EvidenceReliability rel, const std::wstring& name, const std::wstring& err = L"Access Denied") {
        return { T{}, rel, VerificationStatus::ACCESS_DENIED, name, L"", 0.0, err };
    }
};

namespace Weights {
    class WeightResolver;
}

namespace Core {

enum class CollectorState : uint8_t {
    MATCH          = 0,
    MISMATCH       = 1,
    NOT_APPLICABLE = 2,
    UNAVAILABLE    = 3
};

enum class ConflictSeverity : uint8_t {
    NONE   = 0,
    LOW    = 1,
    MEDIUM = 2,
    HIGH   = 3
};

enum class ConsensusConfidence : uint8_t {
    HIGH     = 0,
    WMI_ONLY = 1,
    MODERATE = 2,
    CONFLICT = 3
};

struct CollectorProvenance {
    std::wstring collectorId;
    std::wstring collectorType;
    bool         success   = false;
    int          exitCode  = 0;
    long long    latencyMs = 0;
    long long    initMs    = 0;
    long long    queryMs   = 0;
    long long    parseMs   = 0;
};

struct DualField {
    std::wstring   raw;
    std::wstring   normalized;
    CollectorState state = CollectorState::UNAVAILABLE;
};

struct NormalizedLicenseData {
    bool         success = false;
    DualField    edition;       
    DualField    channel;       
    DualField    status;        
    DualField    partialKey;    
    DualField    kmsMachine;
    std::wstring activationId;
    std::wstring applicationId;
    std::wstring rawOutputText;
    int          unparsedCount = 0;
};

struct CollectorConsensus {
    std::wstring          consensusVersion = L"1.1";
    std::wstring          conflictReasonCode = L"NONE";

    CollectorProvenance   wmiProvenance;
    CollectorProvenance   dlvProvenance;

    NormalizedLicenseData wmiData;
    NormalizedLicenseData dlvData;

    int                 matchedFields  = 0;
    int                 comparedFields = 0;
    ConflictSeverity    conflictLevel  = ConflictSeverity::NONE;
    ConsensusConfidence confidence     = ConsensusConfidence::WMI_ONLY;
    bool                unavailable    = true;
    bool                secondaryAvailable = false;

    double getAgreementPercentage() const {
        if (comparedFields == 0) return 0.0;
        return (static_cast<double>(matchedFields) / comparedFields) * 100.0;
    }

    std::wstring getConfidenceString() const {
        switch (confidence) {
            case ConsensusConfidence::HIGH:     return L"HIGH (Dual-Collector Verified)";
            case ConsensusConfidence::WMI_ONLY: return L"WMI_ONLY (Single-Collector Baseline)";
            case ConsensusConfidence::MODERATE: return L"MODERATE (Minor Discrepancy)";
            case ConsensusConfidence::CONFLICT: return L"CONFLICT (Critical Mismatch Detected)";
            default:                            return L"UNKNOWN";
        }
    }

    std::wstring getConflictLevelString() const {
        switch (conflictLevel) {
            case ConflictSeverity::NONE:   return L"NONE";
            case ConflictSeverity::LOW:    return L"LOW";
            case ConflictSeverity::MEDIUM: return L"MEDIUM";
            case ConflictSeverity::HIGH:   return L"HIGH";
            default:                       return L"UNKNOWN";
        }
    }

    static const wchar_t* collectorStateToString(CollectorState st) {
        switch (st) {
            case CollectorState::MATCH:          return L"MATCH";
            case CollectorState::MISMATCH:       return L"MISMATCH";
            case CollectorState::NOT_APPLICABLE: return L"NOT_APPLICABLE";
            case CollectorState::UNAVAILABLE:    return L"UNAVAILABLE";
            default:                             return L"UNKNOWN";
        }
    }
};

} // namespace Core

struct FindingResult {
    std::wstring        id;
    std::wstring        category;
    std::wstring        detail;
    std::wstring        value;
    Severity            severity;
    bool                flagged;
    bool                available;
    FindingType         type               = FindingType::FORENSIC_EVIDENCE;
    ForensicSource      source             = ForensicSource::NONE;
    EvidenceImpact      impact             = EvidenceImpact::INFO_ONLY;
    EvidenceQuality     quality            = EvidenceQuality::LOW;
    EvidenceReliability reliability        = EvidenceReliability::WEAK;
    VerificationStatus  verificationStatus = VerificationStatus::FOUND;
    FindingState        state              = FindingState::DETECTED;
    int                 ageDays            = -1;
    EvidenceDomain      domain             = EvidenceDomain::WINDOWS;
    EvidenceCategory    evidenceCategory   = EvidenceCategory::WMI;
    FindingRole         role               = FindingRole::PRIMARY;
    FindingDisposition  disposition        = FindingDisposition::NORMAL;
    EvidenceOrigin      origin             = EvidenceOrigin::OBSERVED;
    bool                hasConsensusData   = false;
    Core::CollectorConsensus consensus;

    FindingResult(std::wstring _id, std::wstring _category, std::wstring _detail,
                  std::wstring _value, Severity _severity, bool _flagged, bool _available,
                  FindingType _type = FindingType::FORENSIC_EVIDENCE,
                  ForensicSource _source = ForensicSource::NONE,
                  EvidenceImpact _impact = EvidenceImpact::INFO_ONLY,
                  EvidenceQuality _quality = EvidenceQuality::LOW,
                  EvidenceReliability _reliability = EvidenceReliability::WEAK,
                  VerificationStatus _vStatus = VerificationStatus::FOUND,
                  FindingState _state = FindingState::DETECTED,
                  int _ageDays = -1,
                  EvidenceDomain _domain = EvidenceDomain::WINDOWS,
                  EvidenceCategory _evidenceCat = EvidenceCategory::WMI,
                  FindingRole _role = FindingRole::PRIMARY,
                  FindingDisposition _disposition = FindingDisposition::NORMAL,
                  EvidenceOrigin _origin = EvidenceOrigin::OBSERVED)
        : id(std::move(_id)), category(std::move(_category)), detail(std::move(_detail)),
          value(std::move(_value)), severity(_severity), flagged(_flagged),
          available(_available), type(_type), source(_source), impact(_impact),
          quality(_quality), reliability(_reliability), verificationStatus(_vStatus),
          state(_state), ageDays(_ageDays), domain(_domain), evidenceCategory(_evidenceCat),
          role(_role), disposition(_disposition), origin(_origin)
    {}

    int getWeight() const;

    bool contributesEvidence() const {
        return available && flagged && type == FindingType::FORENSIC_EVIDENCE && getWeight() > 0;
    }

    static FindingResult clean(const std::wstring& id,
                               const std::wstring& category,
                               const std::wstring& detail = L"No anomaly detected.",
                               FindingType fType = FindingType::FORENSIC_EVIDENCE,
                               ForensicSource fSource = ForensicSource::NONE,
                               EvidenceReliability fReliability = EvidenceReliability::VERIFIED,
                               EvidenceDomain fDomain = EvidenceDomain::WINDOWS,
                               EvidenceCategory fCat = EvidenceCategory::WMI,
                               FindingRole fRole = FindingRole::PRIMARY)
    {
        return { id, category, detail, L"", Severity::CLEAN, false, true, fType, fSource,
                 EvidenceImpact::INFO_ONLY, EvidenceQuality::LOW, fReliability,
                 VerificationStatus::FOUND, FindingState::NOT_APPLICABLE, -1,
                 fDomain, fCat, fRole, FindingDisposition::NORMAL, EvidenceOrigin::OBSERVED };
    }

    static FindingResult notApplicable(const std::wstring& id,
                                       const std::wstring& category,
                                       const std::wstring& reason,
                                       FindingType fType = FindingType::CONFIGURATION,
                                       EvidenceDomain fDomain = EvidenceDomain::WINDOWS,
                                       EvidenceCategory fCat = EvidenceCategory::WMI,
                                       FindingRole fRole = FindingRole::PRIMARY)
    {
        return { id, category, reason, L"", Severity::INFO, false, false, fType, ForensicSource::NONE,
                 EvidenceImpact::INFO_ONLY, EvidenceQuality::LOW, EvidenceReliability::VERIFIED,
                 VerificationStatus::NOT_APPLICABLE, FindingState::NOT_APPLICABLE, -1,
                 fDomain, fCat, fRole, FindingDisposition::NORMAL, EvidenceOrigin::OBSERVED };
    }

    static FindingResult unavailable(const std::wstring& id,
                                     const std::wstring& category,
                                     const std::wstring& reason,
                                     FindingType fType = FindingType::CONFIGURATION,
                                     VerificationStatus vStatus = VerificationStatus::NOT_APPLICABLE,
                                     EvidenceDomain fDomain = EvidenceDomain::WINDOWS,
                                     EvidenceCategory fCat = EvidenceCategory::WMI,
                                     FindingRole fRole = FindingRole::PRIMARY)
    {
        return { id, category, reason, L"", Severity::INFO, false, false, fType, ForensicSource::NONE,
                 EvidenceImpact::INFO_ONLY, EvidenceQuality::LOW, EvidenceReliability::WEAK,
                 vStatus, FindingState::UNKNOWN, -1,
                 fDomain, fCat, fRole, FindingDisposition::NORMAL, EvidenceOrigin::OBSERVED };
    }
};

struct SystemInfo {
    std::wstring osName;
    std::wstring osBuild;
    std::wstring hostname;
    std::wstring currentUser;
    std::wstring biosModel;
    std::wstring officeVersion;
    std::wstring oemKey;
    std::wstring currentOsKey;
};

struct ScanSummary {
    int total             = 0;
    int clean             = 0;
    int warning           = 0;
    int tampering         = 0;
    int forensicTampering = 0;
    int licenseAttention  = 0;
    int unavailable       = 0;
    int information       = 0;
    int evidenceScore     = 0;
    int trustScore        = 100;
    int foundCount        = 0;
    int notFoundCount     = 0;
    int notApplicableCount= 0;
    int accessDeniedCount = 0;
    int errorCount        = 0;
    std::wstring trustGauge;
    std::wstring trustLevel;

    static ScanSummary compute(const std::vector<FindingResult>& findings) {
        ScanSummary s;
        for (const auto& f : findings) {
            s.total++;
            if (f.verificationStatus == VerificationStatus::ACCESS_DENIED) {
                s.accessDeniedCount++;
            } else if (f.verificationStatus == VerificationStatus::ERROR_OCCURRED) {
                s.errorCount++;
            } else if (f.verificationStatus == VerificationStatus::NOT_APPLICABLE || f.verificationStatus == VerificationStatus::UNSUPPORTED || !f.available) {
                s.notApplicableCount++;
            } else if (f.verificationStatus == VerificationStatus::NOT_FOUND) {
                s.notFoundCount++;
            } else {
                s.foundCount++;
            }

            if (!f.available) {
                s.unavailable++;
                continue;
            }
            if (f.type == FindingType::INFORMATION || f.severity == Severity::INFO) {
                s.information++;
            }
            if (!f.flagged) {
                s.clean++;
                continue;
            }
            if (f.type == FindingType::FORENSIC_EVIDENCE) {
                if (f.severity == Severity::TAMPERING) {
                    s.tampering++;
                    s.forensicTampering++;
                } else if (f.severity == Severity::WARNING) {
                    s.warning++;
                }
                s.evidenceScore += f.getWeight();
            } else if (f.type == FindingType::LICENSE_STATE) {
                s.licenseAttention++;
                if (f.severity == Severity::WARNING) s.warning++;
            } else {
                if (f.severity == Severity::WARNING) s.warning++;
                else if (f.severity == Severity::TAMPERING) s.tampering++;
            }
        }

        s.trustScore = 100 - (s.evidenceScore + s.warning * 5);
        if (s.trustScore < 0) s.trustScore = 0;

        // Build simple gauge string [########--]
        int filled = s.trustScore / 10;
        s.trustGauge = L"[";
        for (int i = 0; i < 10; ++i) {
            s.trustGauge += (i < filled) ? L"#" : L"-";
        }
        s.trustGauge += L"]";

        if (s.forensicTampering > 0 || s.evidenceScore >= 40) {
            s.trustLevel = L"HIGH RISK OF TAMPERING (Action Required)";
        } else if (s.evidenceScore >= 15 || s.warning > 0) {
            s.trustLevel = L"MODERATE RISK / SUSPICIOUS CONFIGURATION";
        } else if (s.licenseAttention > 0) {
            s.trustLevel = L"LICENSE ATTENTION REQUIRED";
        } else {
            s.trustLevel = L"CLEAN / GENUINE SYSTEM";
        }
        return s;
    }
};

struct EvidenceEdge {
    std::wstring sourceId;
    std::wstring targetId;
    EdgeRelation relation;
    std::wstring detail;
    EdgeStrength strength = EdgeStrength::MEDIUM;
};

struct EvidenceNode {
    const FindingResult*       finding;
    std::vector<EvidenceEdge*> outgoingEdges;
    std::vector<EvidenceEdge*> incomingEdges;
    GraphConfidence            graphConfidence = GraphConfidence::NORMAL;
};

struct SourceSummary {
    std::vector<const FindingResult*> findings;
    int verifiedCount      = 0;
    int strongCount        = 0;
    int moderateCount      = 0;
    int weakCount          = 0;
    int highQualityCount   = 0;
    int mediumQualityCount = 0;
    int lowQualityCount    = 0;
    EvidenceQuality     highestQuality     = EvidenceQuality::LOW;
    EvidenceReliability highestReliability = EvidenceReliability::WEAK;
    EvidenceImpact      highestImpact      = EvidenceImpact::INFO_ONLY;
    bool                activeFinding      = false;
    int                 maxWeight          = 0;
};

struct EvidenceGraph {
    std::vector<EvidenceNode>                         nodes;
    std::vector<EvidenceEdge>                         edges;
    std::unordered_map<ForensicSource, SourceSummary> sourceMatrix;
    int  totalEvaluatedNodes = 0;
    int  uniqueSourceCount   = 0;
    int  confirmedEdgeCount  = 0;
    bool hasActiveTampering  = false;
    bool hasAccessDenied     = false;
};

class EvidenceGraphBuilder {
public:
    static EvidenceGraph build(const std::vector<FindingResult>& findings) {
        EvidenceGraph graph;
        for (const auto& f : findings) {
            if (f.verificationStatus != VerificationStatus::NOT_APPLICABLE && f.verificationStatus != VerificationStatus::UNSUPPORTED && f.available) {
                graph.totalEvaluatedNodes++;
            }
            if (!f.available && f.verificationStatus == VerificationStatus::ACCESS_DENIED) {
                graph.hasAccessDenied = true;
            }
            if (!f.available || !f.flagged) continue;

            EvidenceNode node;
            node.finding = &f;
            node.graphConfidence = GraphConfidence::NORMAL;
            graph.nodes.push_back(node);

            // Populate Source Matrix
            auto& sum = graph.sourceMatrix[f.source];
            sum.findings.push_back(&f);
            if (f.reliability == EvidenceReliability::VERIFIED) sum.verifiedCount++;
            else if (f.reliability == EvidenceReliability::STRONG) sum.strongCount++;
            else if (f.reliability == EvidenceReliability::MODERATE) sum.moderateCount++;
            else if (f.reliability == EvidenceReliability::WEAK) sum.weakCount++;

            if (f.quality == EvidenceQuality::HIGH) sum.highQualityCount++;
            else if (f.quality == EvidenceQuality::MEDIUM) sum.mediumQualityCount++;
            else if (f.quality == EvidenceQuality::LOW) sum.lowQualityCount++;

            if (f.quality > sum.highestQuality) sum.highestQuality = f.quality;
            if (f.reliability > sum.highestReliability) sum.highestReliability = f.reliability;
            if (f.impact > sum.highestImpact) sum.highestImpact = f.impact;

            int w = f.getWeight();
            if (w > sum.maxWeight) sum.maxWeight = w;
            if (f.quality == EvidenceQuality::HIGH && f.reliability >= EvidenceReliability::STRONG && f.type == FindingType::FORENSIC_EVIDENCE) {
                sum.activeFinding = true;
                graph.hasActiveTampering = true;
            }
        }

        for (const auto& [src, sum] : graph.sourceMatrix) {
            if (src != ForensicSource::NONE && !sum.findings.empty() && src != ForensicSource::LICENSE_STATE) {
                graph.uniqueSourceCount++;
            }
        }

        // Build relational edges between nodes
        auto findNode = [&](const std::wstring& id) -> EvidenceNode* {
            for (auto& n : graph.nodes) {
                if (n.finding->id == id) return &n;
            }
            return nullptr;
        };

        auto addEdge = [&](const std::wstring& srcId, const std::wstring& dstId, EdgeRelation rel, const std::wstring& detail, EdgeStrength strength = EdgeStrength::MEDIUM) {
            EvidenceNode* srcNode = findNode(srcId);
            EvidenceNode* dstNode = findNode(dstId);
            if (srcNode && dstNode) {
                graph.edges.push_back({ srcId, dstId, rel, detail, strength });
                EvidenceEdge* edgePtr = &graph.edges.back();
                srcNode->outgoingEdges.push_back(edgePtr);
                dstNode->incomingEdges.push_back(edgePtr);

                if (rel == EdgeRelation::USES || rel == EdgeRelation::SUPPORTS || rel == EdgeRelation::CORROBORATES) {
                    if (srcNode->finding->reliability >= EvidenceReliability::STRONG || dstNode->finding->reliability >= EvidenceReliability::STRONG) {
                        srcNode->graphConfidence = GraphConfidence::CONFIRMED;
                        dstNode->graphConfidence = GraphConfidence::CONFIRMED;
                        graph.confirmedEdgeCount++;
                    }
                }
            }
        };

        // Check specific relational corroborations across checks
        addEdge(L"A9",  L"A6",  EdgeRelation::USES,         L"KMS Windows Service USES hidden Scheduled Task for persistence", EdgeStrength::STRONG);
        addEdge(L"A9",  L"A2",  EdgeRelation::USES,         L"KMS Windows Service executed via PowerShell script history", EdgeStrength::MEDIUM);
        addEdge(L"A10", L"A1",  EdgeRelation::SUPPORTS,     L"Hosts domain redirection SUPPORTS local loopback KMS emulator", EdgeStrength::MEDIUM);
        addEdge(L"A13", L"A11", EdgeRelation::CORROBORATES, L"SPP COM DLL Hijack CORROBORATES SPP store logical contradiction", EdgeStrength::STRONG);
        addEdge(L"A3",  L"A11", EdgeRelation::CORROBORATES, L"KMS38 hook CORROBORATES Volume GVLK state anomaly", EdgeStrength::STRONG);

        // Automatic Role-Driven & Domain-Isolated Corroboration (SIEM/DFIR Attribute Graph)
        for (auto& nodeA : graph.nodes) {
            if (!nodeA.finding->flagged || !nodeA.finding->contributesEvidence() || nodeA.finding->role != FindingRole::SUPPORTING) continue;
            for (auto& nodeB : graph.nodes) {
                if (nodeA.finding->id == nodeB.finding->id || !nodeB.finding->flagged || !nodeB.finding->contributesEvidence()) continue;
                if (nodeA.finding->domain == nodeB.finding->domain && nodeB.finding->role == FindingRole::PRIMARY && nodeB.finding->type == FindingType::FORENSIC_EVIDENCE) {
                    addEdge(nodeA.finding->id, nodeB.finding->id, EdgeRelation::CORROBORATES,
                            nodeA.finding->category + L" CORROBORATES active primary tampering artifact [" + nodeB.finding->id + L"]", EdgeStrength::MEDIUM);
                }
            }
        }

        return graph;
    }
};

enum class VerdictLevel {
    CLEAN,
    LICENSE_ATTENTION,
    SUSPICIOUS_CONFIG,
    EVIDENCE_OF_TAMPERING
};

struct Verdict {
    VerdictLevel              level;
    std::wstring              title;
    std::wstring              description;
    ConfidenceLevel           confidence;
    int                       confidenceIndex = 0; // Heuristic Confidence Index 0-100
    std::wstring              confidenceString;
    std::wstring              riskRanking;
    std::vector<std::wstring> reasons;
    std::vector<std::wstring> recommendations;

    static Verdict compute(const ScanSummary& summary, const std::vector<FindingResult>& findings) {
        EvidenceGraph graph = EvidenceGraphBuilder::build(findings);

        // Calculate Dual-Metric Certainty Index (0-100) using Collection Coverage & Applicable Scope
        int totalChecks = (int)findings.size();
        int notApplicableChecks = 0;
        int accessDeniedChecks = 0;
        int errorChecks = 0;
        double totalReliability = 0.0;
        int activeCollectors = 0;

        for (const auto& f : findings) {
            if (f.verificationStatus == VerificationStatus::NOT_APPLICABLE || f.verificationStatus == VerificationStatus::UNSUPPORTED || !f.available) {
                notApplicableChecks++;
            } else if (f.verificationStatus == VerificationStatus::ACCESS_DENIED) {
                accessDeniedChecks++;
            } else if (f.verificationStatus == VerificationStatus::ERROR_OCCURRED) {
                errorChecks++;
            } else {
                activeCollectors++;
                if (f.reliability == EvidenceReliability::VERIFIED) totalReliability += 1.00;
                else if (f.reliability == EvidenceReliability::STRONG) totalReliability += 0.90;
                else if (f.reliability == EvidenceReliability::MODERATE) totalReliability += 0.70;
                else totalReliability += 0.50;
            }
        }

        int applicableChecks = totalChecks - notApplicableChecks;
        if (applicableChecks <= 0) applicableChecks = 1;

        // Collection Coverage ratio (0.0 to 1.0) based on successful vs applicable collectors
        int successfulChecks = applicableChecks - accessDeniedChecks - errorChecks;
        if (successfulChecks < 0) successfulChecks = 0;
        double collectionCoverage = (double)successfulChecks / (double)applicableChecks;

        // Applicable Scope ratio (0.0 to 1.0) based on applicable vs total checks
        double applicableScope = (totalChecks > 0) ? (double)applicableChecks / (double)totalChecks : 1.0;

        // Average Reliability ratio (0.0 to 1.0)
        double avgReliability = (activeCollectors > 0) ? (totalReliability / activeCollectors) : 1.0;

        // Corroboration multiplier (>= 1.0)
        double corroborationMult = 1.0 + (graph.confirmedEdgeCount * 0.05);

        double rawCertainty = collectionCoverage * avgReliability * corroborationMult * 100.0;
        int index = (int)(rawCertainty + 0.5);

        if (accessDeniedChecks == 0 && errorChecks == 0) {
            if (summary.evidenceScore == 0 && !graph.hasActiveTampering) {
                if (collectionCoverage >= 0.99 && applicableScope >= 0.99) {
                    index = 100;
                } else if (collectionCoverage >= 0.99) {
                    index = static_cast<int>(80.0 + 20.0 * applicableScope + 0.5);
                    if (index < 96) index = 96;
                    if (index > 99) index = 99;
                }
            } else if (graph.confirmedEdgeCount > 0 || summary.evidenceScore >= 40) {
                if (index < 96) index = 96;
            }
        } else {
            index -= (accessDeniedChecks * 15 + errorChecks * 12);
        }

        if (index < 0) index = 0;
        if (index > 100) index = 100;

        ConfidenceLevel confLevel = ConfidenceLevel::LOW;
        std::wstring confStr;
        if (index == 100) {
            confLevel = ConfidenceLevel::VERY_HIGH;
            confStr = L"VERY HIGH (" + std::to_wstring(index) + L"/100) - All applicable collectors completed cleanly without errors.";
        } else if (index >= 90) {
            confLevel = ConfidenceLevel::VERY_HIGH;
            confStr = L"VERY HIGH (" + std::to_wstring(index) + L"/100) - High coverage across verified data sources with strong corroboration.";
        } else if (index >= 75 || graph.hasActiveTampering) {
            confLevel = ConfidenceLevel::HIGH;
            confStr = L"HIGH (" + std::to_wstring(index) + L"/100) - High coverage across verified data sources.";
        } else if (index >= 50 || graph.uniqueSourceCount >= 2) {
            confLevel = ConfidenceLevel::MEDIUM;
            confStr = L"MEDIUM (" + std::to_wstring(index) + L"/100) - Partial collector coverage or access denied encountered.";
        } else {
            confStr = L"LOW (" + std::to_wstring(index) + L"/100) - Access denied or collector errors significantly impacted verification.";
        }

        // Risk Ranking based on EvidenceScore
        std::wstring riskStr = L"LOW RISK (Evidence Score: " + std::to_wstring(summary.evidenceScore) + L")";
        if (summary.evidenceScore >= 40) riskStr = L"CRITICAL RISK (Evidence Score: " + std::to_wstring(summary.evidenceScore) + L" - High Impact Tampering)";
        else if (summary.evidenceScore >= 15) riskStr = L"MODERATE RISK (Evidence Score: " + std::to_wstring(summary.evidenceScore) + L" - Suspicious Persistence)";

        // Attribute-Based & SIEM/DFIR Origin Rule Inference
        bool hasObservedTampering = false;
        bool hasCorrelatedTampering = false;
        for (const auto& node : graph.nodes) {
            if (node.finding->flagged && node.finding->contributesEvidence()) {
                if (node.finding->origin == EvidenceOrigin::OBSERVED) hasObservedTampering = true;
                if (node.finding->origin == EvidenceOrigin::CORRELATED) hasCorrelatedTampering = true;
            }
        }

        VerdictLevel vLevel = VerdictLevel::CLEAN;
        std::wstring title = L"CLEAN";
        std::wstring desc  = L"No forensic artifacts or unauthorized activation mechanisms detected. System appears genuine.";

        if (graph.hasActiveTampering || (hasObservedTampering && hasCorrelatedTampering) || (graph.uniqueSourceCount >= 2 && index >= 60) || graph.confirmedEdgeCount > 0) {
            vLevel = VerdictLevel::EVIDENCE_OF_TAMPERING;
            title = L"EVIDENCE OF LICENSE TAMPERING";
            desc  = L"Forensic evidence collected across independent system layers confirms the presence of unauthorized activation tools, active hooks, or modified license behaviors.";
        } else if (summary.evidenceScore >= 10 || graph.uniqueSourceCount >= 1 || graph.hasAccessDenied) {
            vLevel = VerdictLevel::SUSPICIOUS_CONFIG;
            title = L"SUSPICIOUS CONFIGURATION";
            desc  = L"Suspicious configurations, dormant crack artifacts, or restricted registry access detected. Manual review recommended.";
        } else if (summary.licenseAttention > 0) {
            vLevel = VerdictLevel::LICENSE_ATTENTION;
            title = L"LICENSE ATTENTION REQUIRED";
            desc  = L"No crack artifacts detected, but Office or Windows license requires attention (Out-of-Box Grace, Notification state, or pending activation).";
        }

        // Collect Reasons from Graph Nodes with Attributes
        std::vector<std::wstring> rs;
        for (const auto& node : graph.nodes) {
            const auto* f = node.finding;
            if (!f->flagged || f->type == FindingType::INFORMATION) continue;
            std::wstring relTag = L"WEAK";
            if (f->reliability == EvidenceReliability::VERIFIED) relTag = L"VERIFIED";
            else if (f->reliability == EvidenceReliability::STRONG) relTag = L"STRONG";
            else if (f->reliability == EvidenceReliability::MODERATE) relTag = L"MODERATE";

            std::wstring qualTag = L"LOW";
            if (f->quality == EvidenceQuality::HIGH) qualTag = L"HIGH";
            else if (f->quality == EvidenceQuality::MEDIUM) qualTag = L"MEDIUM";

            std::wstring originTag = (f->origin == EvidenceOrigin::OBSERVED) ? L"OBSERVED" : (f->origin == EvidenceOrigin::CORRELATED) ? L"CORRELATED" : L"DERIVED";
            std::wstring graphTag = (node.graphConfidence == GraphConfidence::CONFIRMED) ? L"/CONFIRMED" : L"";
            rs.push_back(L"[" + f->id + L"] [" + originTag + L"|" + relTag + L"/" + qualTag + graphTag + L"] " + f->detail);
        }

        // Generate Remediations from Data-Driven RemediationEngine
        Verdict tempV = { vLevel, title, desc, confLevel, index, confStr, riskStr, rs, {} };
        std::vector<std::wstring> recs = Remediation::RemediationEngine::computeRemediations(findings, tempV);

        tempV.recommendations = std::move(recs);
        return tempV;
    }

    static Verdict compute(const ScanSummary& summary) {
        return compute(summary, {});
    }
};

inline std::vector<std::wstring> Remediation::RemediationEngine::computeRemediations(const std::vector<FindingResult>& findings, const Verdict& verdict) {
    std::vector<std::wstring> recs;
    if (verdict.level == VerdictLevel::CLEAN) {
        recs.push_back(L"No immediate remediation actions required. System licensing state and forensic indicators are clean.");
        return recs;
    }
    for (const auto& f : findings) {
        if (!f.flagged || !f.available) continue;
        for (const auto& entry : REMEDIATION_TABLE) {
            if (f.id == entry.id) {
                recs.push_back(StringFormatter::safeFormat(entry.actionTemplate, f.value));
                break;
            }
        }
    }
    if (recs.empty() && verdict.level != VerdictLevel::CLEAN) {
        recs.push_back(L"Perform manual inspection of flagged warnings using 'slmgr /dlv' and verify corporate licensing policies.");
    }
    return recs;
}


enum class OutputFormat {
    CONSOLE_ONLY,
    CONSOLE_AND_TXT,
    CONSOLE_AND_JSON,
    CONSOLE_AND_BOTH,
};

} // namespace LicenseInspector

#include "evidence_weights.h"

namespace LicenseInspector {

inline int FindingResult::getWeight() const {
    if (!available || !flagged || type != FindingType::FORENSIC_EVIDENCE) return 0;
    return Weights::WeightResolver::resolve(*this);
}

namespace Weights {
    inline int WeightResolver::resolve(const FindingResult& finding) {
        // Formula: Role x Impact x Reliability
        int roleMult = 10;
        if (finding.role == FindingRole::PRIMARY) roleMult = 30;
        else if (finding.role == FindingRole::SUPPORTING) roleMult = 15;
        else if (finding.role == FindingRole::CORROBORATIVE) roleMult = 20;

        double impactMult = 1.0;
        if (finding.impact == EvidenceImpact::HIGH) impactMult = 1.3;
        else if (finding.impact == EvidenceImpact::MEDIUM) impactMult = 1.0;
        else if (finding.impact == EvidenceImpact::LOW) impactMult = 0.5;

        double relMult = 1.0;
        if (finding.reliability == EvidenceReliability::VERIFIED) relMult = 1.0;
        else if (finding.reliability == EvidenceReliability::STRONG) relMult = 0.8;
        else if (finding.reliability == EvidenceReliability::MODERATE) relMult = 0.6;
        else if (finding.reliability == EvidenceReliability::WEAK) relMult = 0.4;
        else relMult = 0.2;

        double baseWeight = roleMult * impactMult * relMult;

        // Apply soft decay if ageDays > 0
        if (finding.ageDays > 0) {
            if (finding.ageDays > 180) baseWeight *= 0.5;
            else if (finding.ageDays > 90) baseWeight *= 0.75;
            else if (finding.ageDays > 30) baseWeight *= 0.9;
        }

        int w = static_cast<int>(baseWeight + 0.5);
        return (w < 0) ? 0 : w;
    }
} // namespace Weights

} // namespace LicenseInspector
