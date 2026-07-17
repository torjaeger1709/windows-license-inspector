#pragma once
#include <string>
#include <vector>
#include <regex>
#include <sstream>
#include <iomanip>
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#include "types.h"

namespace LicenseInspector {

struct EditionTokenRule {
    const wchar_t* pattern; // regex pattern
    int            priority;
    LicenseEdition edition;
};

struct ChannelTokenRule {
    const wchar_t* pattern;
    int            priority;
    LicenseChannel channel;
};

// Data-Driven Priority Table for Edition Parsing (Regex + Priority Score)
inline constexpr EditionTokenRule EDITION_TABLE[] = {
    { L"(?:ProfessionalWorkstation|Pro\\s*Workstation)",  100, LicenseEdition::PROFESSIONAL },
    { L"(?:ProfessionalEducation|Pro\\s*Education)",      95,  LicenseEdition::PROFESSIONAL },
    { L"(?:ProfessionalCountrySpecific|Pro\\s*Single)",   90,  LicenseEdition::PROFESSIONAL },
    { L"(?:Professional|Pro(?:fessional)?\\b)",           80,  LicenseEdition::PROFESSIONAL },
    { L"(?:Enterprise\\s*LTSC|LTSC)",                     85,  LicenseEdition::LTSC },
    { L"(?:Enterprise)",                                  70,  LicenseEdition::ENTERPRISE },
    { L"(?:Education)",                                   70,  LicenseEdition::EDUCATION },
    { L"(?:Server\\b|Datacenter|Standard\\b)",            75,  LicenseEdition::SERVER },
    { L"(?:IoT\\b)",                                      75,  LicenseEdition::IOT },
    { L"(?:CoreSingleLanguage|Home\\s*Single\\s*Language|SL\\b|SingleLanguage)", 65, LicenseEdition::CORE_HOME_SL },
    { L"(?:CoreCountrySpecific|CoreConnected|CountrySpecific|CS\\b)", 65, LicenseEdition::CORE_HOME },
    { L"(?:Core|Home)\\b",                                50,  LicenseEdition::CORE_HOME }
};

// Data-Driven Priority Table for Channel Parsing
inline constexpr ChannelTokenRule CHANNEL_TABLE[] = {
    { L"(?:OEM_DM|OEM:DM|DM)",                            100, LicenseChannel::OEM_DM },
    { L"(?:OEM_NONSLP|OEM:NONSLP|System\\s*Locked)",      90,  LicenseChannel::OEM_NONSLP },
    { L"(?:OEM_COA|OEM:COA|COA)",                         85,  LicenseChannel::OEM_COA },
    { L"(?:VOLUME_KMSCLIENT|KMSClient|GVLK)",             95,  LicenseChannel::VOLUME_GVLK },
    { L"(?:VOLUME_MAK|MAK)",                              90,  LicenseChannel::VOLUME_MAK },
    { L"(?:Retail)",                                      80,  LicenseChannel::RETAIL },
    { L"(?:Digital\\s*License|Digital\\s*Entitlement)",   85,  LicenseChannel::DIGITAL_ENTITLEMENT }
};

class LicenseParser {
public:
    static LicenseEdition parseEditionRegex(const std::wstring& desc, const std::wstring& name) {
        std::wstring combined = name + L" " + desc;
        int bestPriority = -1;
        LicenseEdition bestEdition = LicenseEdition::UNKNOWN;

        for (const auto& rule : EDITION_TABLE) {
            if (rule.priority > bestPriority) {
                try {
                    std::wregex re(rule.pattern, std::regex_constants::icase);
                    if (std::regex_search(combined, re)) {
                        bestPriority = rule.priority;
                        bestEdition = rule.edition;
                    }
                } catch (...) {
                    continue;
                }
            }
        }
        return bestEdition;
    }

    static LicenseChannel parseChannelRegex(const std::wstring& desc, const std::wstring& name) {
        std::wstring combined = name + L" " + desc;
        int bestPriority = -1;
        LicenseChannel bestChannel = LicenseChannel::UNKNOWN;

        for (const auto& rule : CHANNEL_TABLE) {
            if (rule.priority > bestPriority) {
                try {
                    std::wregex re(rule.pattern, std::regex_constants::icase);
                    if (std::regex_search(combined, re)) {
                        bestPriority = rule.priority;
                        bestChannel = rule.channel;
                    }
                } catch (...) {
                    continue;
                }
            }
        }
        return bestChannel;
    }

    static ActivationMechanism parseMechanism(const std::wstring& desc, const std::wstring& name, const std::wstring& kmsMachine, int status) {
        std::wstring combined = name + L" " + desc;
        
        // Check for AVMA
        if (combined.find(L"AVMA") != std::wstring::npos || combined.find(L"Automatic Virtual Machine") != std::wstring::npos) {
            return ActivationMechanism::AVMA;
        }
        // Check for Token-based / Subscription activation
        if (combined.find(L"Subscription") != std::wstring::npos || combined.find(L"Token") != std::wstring::npos) {
            return ActivationMechanism::TOKEN_BASED;
        }
        // Check KMS vs GVLK Installed
        if (combined.find(L"KMS") != std::wstring::npos || combined.find(L"VOLUME_KMSCLIENT") != std::wstring::npos || combined.find(L"GVLK") != std::wstring::npos) {
            if (status == 1 || !kmsMachine.empty()) {
                return ActivationMechanism::KMS_ACTIVATED;
            } else {
                return ActivationMechanism::GVLK_INSTALLED;
            }
        }
        // Check OEM vs Retail vs MAK vs Digital
        if (combined.find(L"OEM") != std::wstring::npos || combined.find(L"DM") != std::wstring::npos) {
            return ActivationMechanism::OEM_HARDWARE;
        }
        if (combined.find(L"MAK") != std::wstring::npos) {
            return ActivationMechanism::MAK_KEY;
        }
        if (combined.find(L"Digital") != std::wstring::npos) {
            return ActivationMechanism::DIGITAL_ENTITLEMENT;
        }
        if (combined.find(L"Retail") != std::wstring::npos) {
            return ActivationMechanism::RETAIL_KEY;
        }
        return ActivationMechanism::UNKNOWN;
    }

    static LicenseProgram parseProgram(const std::wstring& desc, const std::wstring& name) {
        std::wstring combined = name + L" " + desc;
        if (combined.find(L"Subscription") != std::wstring::npos || combined.find(L"M365") != std::wstring::npos) {
            return LicenseProgram::M365_SUBSCRIPTION;
        }
        if (combined.find(L"Entra") != std::wstring::npos || combined.find(L"AAD") != std::wstring::npos || combined.find(L"Azure AD") != std::wstring::npos) {
            return LicenseProgram::ENTRA_ID_AAD;
        }
        if (combined.find(L"Academic") != std::wstring::npos || combined.find(L"Education") != std::wstring::npos) {
            return LicenseProgram::ACADEMIC_EES;
        }
        if (combined.find(L"VOLUME") != std::wstring::npos || combined.find(L"KMS") != std::wstring::npos || combined.find(L"MAK") != std::wstring::npos) {
            return LicenseProgram::VOLUME_LICENSE;
        }
        if (combined.find(L"OEM") != std::wstring::npos || combined.find(L"DM") != std::wstring::npos) {
            return LicenseProgram::OEM_PERPETUAL;
        }
        if (combined.find(L"Retail") != std::wstring::npos) {
            return LicenseProgram::RETAIL_PERPETUAL;
        }
        return LicenseProgram::UNKNOWN;
    }

    // Win32 BCrypt NIST-Compliant SHA-256 Hash
    static std::wstring computeSha256BCrypt(const std::wstring& input) {
        if (input.empty()) return L"";

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (status != 0 || !hAlg) return L"BCryptOpenError";

        DWORD cbHash = 0, cbData = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(cbHash), &cbData, 0);
        if (status != 0 || cbHash == 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return L"BCryptPropError";
        }

        std::vector<BYTE> pbHash(cbHash);
        status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        if (status != 0 || !hHash) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return L"BCryptCreateHashError";
        }

        BCryptHashData(hHash, (PBYTE)input.data(), (ULONG)(input.size() * sizeof(wchar_t)), 0);
        BCryptFinishHash(hHash, pbHash.data(), cbHash, 0);

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        std::wstringstream wss;
        for (BYTE b : pbHash) {
            wss << std::hex << std::setw(2) << std::setfill(L'0') << b;
        }
        return wss.str();
    }

    static std::wstring maskKeyLast5(const std::wstring& rawKey) {
        if (rawKey.empty()) return L"";
        std::wstring cleanKey;
        for (wchar_t c : rawKey) {
            if (c != L' ' && c != L'\t' && c != L'\r' && c != L'\n') cleanKey += c;
        }
        if (cleanKey.size() < 5) return cleanKey;
        std::wstring last5 = cleanKey.substr(cleanKey.size() - 5);
        return L"XXXXX-XXXXX-XXXXX-XXXXX-" + last5;
    }
};

} // namespace LicenseInspector
