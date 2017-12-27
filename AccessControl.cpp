#include <android-base/logging.h>
#include <hidl-util/FQName.h>
#include <log/log.h>

#include "AccessControl.h"

namespace android {

static const char *kPermissionAdd = "add";
static const char *kPermissionGet = "find";
static const char *kPermissionList = "list";

struct audit_data {
    const char* interfaceName;
    pid_t       pid;
};

using android::FQName;

AccessControl::AccessControl() {
#if !defined(DISABLE_SELINUX)
    mSeHandle = selinux_android_hw_service_context_handle();
    LOG_ALWAYS_FATAL_IF(mSeHandle == NULL, "Failed to acquire SELinux handle.");

    if (getcon(&mSeContext) != 0) {
        LOG_ALWAYS_FATAL("Failed to acquire hwservicemanager context.");
    }

    selinux_status_open(true);

    mSeCallbacks.func_audit = AccessControl::auditCallback;
    selinux_set_callback(SELINUX_CB_AUDIT, mSeCallbacks);

    mSeCallbacks.func_log = selinux_log_callback; /* defined in libselinux */
    selinux_set_callback(SELINUX_CB_LOG, mSeCallbacks);
#endif
}

bool AccessControl::canAdd(const std::string& fqName, pid_t pid) {
    FQName fqIface(fqName);

    if (!fqIface.isValid()) {
        return false;
    }
    const std::string checkName = fqIface.package() + "::" + fqIface.name();

    return checkPermission(pid, kPermissionAdd, checkName.c_str());
}

bool AccessControl::canGet(const std::string& fqName, pid_t pid) {
    FQName fqIface(fqName);

    if (!fqIface.isValid()) {
        return false;
    }
    const std::string checkName = fqIface.package() + "::" + fqIface.name();

    return checkPermission(pid, kPermissionGet, checkName.c_str());
}

bool AccessControl::canList(pid_t pid) {
#if !defined(DISABLE_SELINUX)
    return checkPermission(pid, mSeContext, kPermissionList, nullptr);
#else
    return checkPermission(pid, NULL, kPermissionList, nullptr);
#endif
}

bool AccessControl::checkPermission(pid_t sourcePid, const char *targetContext,
                                    const char *perm, const char *interface) {
#if !defined(DISABLE_SELINUX)
    char *sourceContext = NULL;
    bool allowed = false;
    struct audit_data ad;

    if (getpidcon(sourcePid, &sourceContext) < 0) {
        ALOGE("SELinux: failed to retrieved process context for pid %d", sourcePid);
        return false;
    }

    ad.pid = sourcePid;
    ad.interfaceName = interface;

    allowed = (selinux_check_access(sourceContext, targetContext, "hwservice_manager",
                                    perm, (void *) &ad) == 0);

    freecon(sourceContext);

    return allowed;
#else
    (void) sourcePid;
    (void) targetContext;
    (void) perm;
    (void) interface;

    return true;
#endif
}

bool AccessControl::checkPermission(pid_t sourcePid, const char *perm, const char *interface) {
    char *targetContext = NULL;
    bool allowed = false;

#if !defined(DISABLE_SELINUX)
    // Lookup service in hwservice_contexts
    if (selabel_lookup(mSeHandle, &targetContext, interface, 0) != 0) {
        ALOGE("No match for interface %s in hwservice_contexts", interface);
        return false;
    }
#endif

    allowed = checkPermission(sourcePid, targetContext, perm, interface);

#if !defined(DISABLE_SELINUX)
    freecon(targetContext);
#endif

    return allowed;
}

#if !defined(DISABLE_SELINUX)
int AccessControl::auditCallback(void *data, security_class_t /*cls*/, char *buf, size_t len) {
    struct audit_data *ad = (struct audit_data *)data;

    if (!ad || !ad->interfaceName) {
        ALOGE("No valid hwservicemanager audit data");
        return 0;
    }

    snprintf(buf, len, "interface=%s pid=%d", ad->interfaceName, ad->pid);
    return 0;
}
#endif

} // namespace android
