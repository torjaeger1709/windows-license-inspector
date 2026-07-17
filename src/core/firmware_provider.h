#pragma once
#include <string>
#include <vector>
#include <memory>
#include "common/types.h"
#include "common/license_parser.h"
#include "core/wmi_query.h"

namespace LicenseInspector::Core {

class IFirmwareProvider {
public:
    virtual ~IFirmwareProvider() = default;
    virtual bool probe(WMI::WmiClient& wmi) = 0;
    virtual bool extract(WMI::WmiClient& wmi, FirmwareLicenseInfo& info) = 0;
    virtual const wchar_t* getName() const = 0;
};

class Oa3MsdmProvider : public IFirmwareProvider {
public:
    const wchar_t* getName() const override { return L"OA3 MSDM Table Provider"; }

    bool probe(WMI::WmiClient& wmi) override {
        if (!wmi.isConnected()) return false;
        auto rows = wmi.query(L"SELECT OA3xOriginalProductKey FROM SoftwareLicensingService");
        if (rows.empty()) return false;
        auto it = rows[0].find(L"OA3xOriginalProductKey");
        if (it != rows[0].end() && !it->second.empty()) {
            return true;
        }
        return false;
    }

    bool extract(WMI::WmiClient& wmi, FirmwareLicenseInfo& info) override {
        if (!wmi.isConnected()) return false;

        auto rows = wmi.query(L"SELECT OA3xOriginalProductKey, OA3xOriginalProductKeyDescription FROM SoftwareLicensingService");
        if (rows.empty()) return false;

        std::wstring rawKey;
        auto itKey = rows[0].find(L"OA3xOriginalProductKey");
        if (itKey != rows[0].end()) rawKey = itKey->second;

        std::wstring descRaw;
        auto itDesc = rows[0].find(L"OA3xOriginalProductKeyDescription");
        if (itDesc != rows[0].end()) descRaw = itDesc->second;

        if (rawKey.empty() && descRaw.empty()) {
            info.firmwarePresent = false;
            return false;
        }

        info.firmwarePresent = !rawKey.empty();
        if (!rawKey.empty()) {
            info.firmwareKeyHash = LicenseParser::computeSha256BCrypt(rawKey);
            info.firmwarePartialKey = LicenseParser::maskKeyLast5(rawKey);
        }
        info.firmwareDescRaw = descRaw;
        info.firmwareEdition = LicenseParser::parseEditionRegex(descRaw, L"");
        info.firmwareChannel = LicenseParser::parseChannelRegex(descRaw, L"");

        // Query active/installed product info from SoftwareLicensingProduct
        auto products = wmi.query(L"SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL");
        bool foundActive = false;
        for (const auto& p : products) {
            std::wstring statusStr;
            auto itS = p.find(L"LicenseStatus");
            if (itS != p.end()) statusStr = itS->second;

            int statusVal = 0;
            try { if (!statusStr.empty()) statusVal = std::stoi(statusStr); } catch (...) {}

            std::wstring nameRaw, pDescRaw, kmsMachine;
            auto itN = p.find(L"Name");
            if (itN != p.end()) nameRaw = itN->second;
            auto itD = p.find(L"Description");
            if (itD != p.end()) pDescRaw = itD->second;
            auto itK = p.find(L"KeyManagementServiceMachine");
            if (itK != p.end()) kmsMachine = itK->second;

            if (!foundActive || statusVal == 1) {
                if (statusVal == 1) foundActive = true;
                info.currentNameRaw = nameRaw;
                info.currentDescRaw = pDescRaw;
                info.kmsMachine = kmsMachine;
                info.licenseStatus = statusVal;
                info.currentEdition = LicenseParser::parseEditionRegex(pDescRaw, nameRaw);
                info.currentChannel = LicenseParser::parseChannelRegex(pDescRaw, nameRaw);
                info.currentMechanism = LicenseParser::parseMechanism(pDescRaw, nameRaw, kmsMachine, statusVal);
                info.currentProgram = LicenseParser::parseProgram(pDescRaw, nameRaw);
            }
        }

        std::wstring combinedCur = info.currentNameRaw + L" " + info.currentDescRaw;
        if (combinedCur.find(L"Digital") != std::wstring::npos) {
            info.digitalEntitlement = true;
        }
        if (info.currentMechanism == ActivationMechanism::AVMA) {
            info.virtualMachine = true;
        }

        return true;
    }
};

class Oa2SlicProvider : public IFirmwareProvider {
public:
    const wchar_t* getName() const override { return L"OA2.1 SLIC Table Provider"; }
    bool probe(WMI::WmiClient& wmi) override {
        (void)wmi;
        return false;
    }
    bool extract(WMI::WmiClient& wmi, FirmwareLicenseInfo& info) override {
        (void)wmi; (void)info;
        return false;
    }
};

class VirtualFirmwareProvider : public IFirmwareProvider {
public:
    const wchar_t* getName() const override { return L"Virtual Machine Hypervisor Provider"; }
    bool probe(WMI::WmiClient& wmi) override {
        if (!wmi.isConnected()) return false;
        auto rows = wmi.query(L"SELECT * FROM Win32_ComputerSystem");
        if (!rows.empty()) {
            auto it = rows[0].find(L"Model");
            if (it != rows[0].end()) {
                std::wstring model = it->second;
                if (model.find(L"Virtual") != std::wstring::npos || model.find(L"VMware") != std::wstring::npos ||
                    model.find(L"VBOX") != std::wstring::npos || model.find(L"Hyper-V") != std::wstring::npos ||
                    model.find(L"KVM") != std::wstring::npos || model.find(L"QEMU") != std::wstring::npos) {
                    return true;
                }
            }
        }
        return false;
    }
    bool extract(WMI::WmiClient& wmi, FirmwareLicenseInfo& info) override {
        if (probe(wmi)) {
            info.virtualMachine = true;
            return true;
        }
        return false;
    }
};

class FirmwareProviderFactory {
public:
    static std::vector<std::unique_ptr<IFirmwareProvider>> createProviders() {
        std::vector<std::unique_ptr<IFirmwareProvider>> list;
        list.push_back(std::make_unique<Oa3MsdmProvider>());
        list.push_back(std::make_unique<Oa2SlicProvider>());
        list.push_back(std::make_unique<VirtualFirmwareProvider>());
        return list;
    }

    static bool extractConsolidatedInfo(WMI::WmiClient& wmi, FirmwareLicenseInfo& outInfo) {
        auto providers = createProviders();
        bool anyExtracted = false;
        for (auto& p : providers) {
            if (p->probe(wmi)) {
                if (p->extract(wmi, outInfo)) {
                    anyExtracted = true;
                }
            }
        }
        return anyExtracted;
    }
};

} // namespace LicenseInspector::Core
