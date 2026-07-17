#pragma once
#include "core/dlv_collector.h"

namespace LicenseInspector::WMI { class WmiClient; }

namespace LicenseInspector::Core {

class LicenseDataCache {
public:
    static void warmUp(WMI::WmiClient* wmi);

    static const CollectorConsensus& getConsensus();

    static void clear();

    static void invalidate();

    static void refresh(WMI::WmiClient* wmi);

private:
    static CollectorConsensus s_cachedConsensus;
    static bool               s_isWarmedUp;
};

} // namespace LicenseInspector::Core
