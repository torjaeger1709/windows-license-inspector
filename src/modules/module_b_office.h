#pragma once
#include "common/types.h"
#include "core/wmi_query.h"
#include <string>
#include <vector>

namespace LicenseInspector::ModuleB {

std::vector<FindingResult> queryOfficeWmi(WMI::WmiClient& wmi);

std::vector<FindingResult> parseOsppVbs();

std::vector<FindingResult> checkOfficeDigitalLicense();

std::vector<FindingResult> runAll(WMI::WmiClient& wmi);

} // namespace LicenseInspector::ModuleB
